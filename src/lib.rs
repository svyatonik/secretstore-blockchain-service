use std::collections::{BTreeSet, HashSet};
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};
use futures::{future::{ready, BoxFuture, Either}, FutureExt, Stream, StreamExt};
use log::{error, warn};
use parking_lot::RwLock;
use ethereum_types::{U256, BigEndianHash};

use parity_secretstore_primitives::{KeyServerId, ServerKey, ServerKeyId, error::Error, key_server::KeyServer, service::ServiceTask, requester::Requester, DocumentKeyCommon, EncryptedDocumentKeyShadow};

/// Blockchain service tasks.
pub enum BlockchainServiceTask {
	/// Regular service task.
	Regular(ServiceTask),
	///
	RetrieveShadowDocumentKeyCommon(ServerKeyId, Requester),
	///
	RetrieveShadowDocumentKeyPersonal(ServerKeyId, Requester),
}

/// Block API.
pub trait Block: Send + Sync {
	/// New blocks iterator.
	type NewBlocksIterator: Iterator<Item = BlockchainServiceTask>;
	/// Pending tasks iterator.
	type PendingBlocksIterator: Iterator<Item = BlockchainServiceTask>;

	/// Get all new service tasks from this block.
	fn new_tasks(&self) -> Self::NewBlocksIterator;
	/// Get all pending service tasks at this block.
	fn pending_tasks(&self) -> Self::PendingBlocksIterator;
	/// Returns current key server set at this block.
	fn current_key_servers_set(&self) -> BTreeSet<KeyServerId>;
}

/// Futures executor.
pub trait Executor: Send + Sync + 'static {
	/// Spawn future and run to completion.
	fn spawn(&self, future: BoxFuture<()>);
}

/// Transaction pool API.
pub trait TransactionPool: Send + Sync + 'static {
	/// Publish generated server key.
	fn publish_generated_server_key(&self, key_id: ServerKeyId, key: ServerKey);
	/// Publish server key generation error.
	fn publish_server_key_generation_error(&self, key_id: ServerKeyId);
	///
	fn publish_retrieved_server_key(&self, key_id: ServerKeyId, key: ServerKey);
	///
	fn publish_server_key_retrieval_error(&self, key_id: ServerKeyId);
	///
	fn publish_stored_document_key(&self, key_id: ServerKeyId);
	///
	fn publish_document_key_store_error(&self, key_id: ServerKeyId);
	///
	fn publish_retrieved_document_key_common(&self, key_id: ServerKeyId, requester: Requester, key_common: DocumentKeyCommon);
	///
	fn publish_document_key_common_retrieval_error(&self, key_id: ServerKeyId, requester: Requester);
	///
	fn publish_retrieved_document_key_personal(&self, key_id: ServerKeyId, requester: Requester, key_personal: EncryptedDocumentKeyShadow);
	///
	fn publish_document_key_personal_retrieval_error(&self, key_id: ServerKeyId, requester: Requester);
}

/// Service configuration.
pub struct Configuration {
	/// Id of this key server.
	pub self_id: KeyServerId,
	/// Maximal number of active sessions started by this service.
	/// None means that there's no limit.
	pub max_active_sessions: Option<usize>,
	/// Pending tasks restart interval.
	/// None means that pending tasks are never restarted.
	pub pending_restart_interval: Option<Duration>,
}

/// Service environment.
struct Environment<E, TP, KS> {
	/// This key server id.
	pub self_id: KeyServerId,
	/// Futures executor reference.
	pub executor: Arc<E>,
	/// Transaction pool reference.
	pub transaction_pool: Arc<TP>,
	/// Key server reference.
	pub key_server: Arc<KS>,
}

/// Shared service data.
struct ServiceData {
	/// Last pending tasks restart time.
	pub last_restart_time: Instant,
	/// Active server key generation sessions started by this service.
	pub server_key_generation_sessions: HashSet<ServerKeyId>,
	/// Recently completed (with or without error) server key generation sessions,
	/// started by this service.
	pub recent_server_key_generation_sessions: HashSet<ServerKeyId>,
	///
	pub server_key_retrieval_sessions: HashSet<ServerKeyId>,
	///
	pub recent_server_key_retrieval_sessions: HashSet<ServerKeyId>,
	///
	pub document_key_store_sessions: HashSet<ServerKeyId>,
	///
	pub recent_document_key_store_sessions: HashSet<ServerKeyId>,
	///
	pub document_key_common_retrieval_sessions: HashSet<(ServerKeyId, Requester)>,
	///
	pub recent_document_key_common_retrieval_sessions: HashSet<(ServerKeyId, Requester)>,
	///
	pub document_key_personal_retrieval_sessions: HashSet<(ServerKeyId, Requester)>,
	///
	pub recent_document_key_personal_retrieval_sessions: HashSet<(ServerKeyId, Requester)>,
}

/// Start listening requests from given contract.
pub async fn start_service<B, E, TP, KS>(
	key_server: Arc<KS>,
	executor: Arc<E>,
	transaction_pool: Arc<TP>,
	config: Configuration,
	new_blocks_stream: impl Stream<Item = B>,
) -> Result<(), Error> where
	B: Block,
	E: Executor,
	TP: TransactionPool,
	KS: KeyServer,
{
	let environment = Arc::new(Environment {
		self_id: config.self_id,
		executor,
		transaction_pool,
		key_server,
	});
	let service_data = Arc::new(RwLock::new(ServiceData {
		last_restart_time: Instant::now(),
		server_key_generation_sessions: HashSet::new(),
		recent_server_key_generation_sessions: HashSet::new(),
		server_key_retrieval_sessions: HashSet::new(),
		recent_server_key_retrieval_sessions: HashSet::new(),
		document_key_store_sessions: HashSet::new(),
		recent_document_key_store_sessions: HashSet::new(),
		document_key_common_retrieval_sessions: HashSet::new(),
		recent_document_key_common_retrieval_sessions: HashSet::new(),
		document_key_personal_retrieval_sessions: HashSet::new(),
		recent_document_key_personal_retrieval_sessions: HashSet::new(),
	}));

	new_blocks_stream
		.for_each(|block| {
			// we do not want to overload Secret Store, so let's limit number of possible active sessions
			let future_service_data = service_data.clone();
			let mut service_data = service_data.write();
			let num_active_sessions = service_data.active_sessions();
			let mut max_additional_sessions = config
				.max_active_sessions
				.unwrap_or(std::usize::MAX)
				.checked_sub(num_active_sessions)
				.unwrap_or(0);

			// we need to know current key servers set to distribute tasks among nodes
			let current_set = block.current_key_servers_set();

			// first, process new tasks
			max_additional_sessions -= process_tasks(
				&environment,
				&future_service_data,
				&current_set,
				block.new_tasks().take(max_additional_sessions),
				&mut service_data,
			);

			// if enough time has passed since last tasks restart, let's start them now
			if let Some(pending_restart_interval) = config.pending_restart_interval {
				let last_restart_time = service_data.last_restart_time;
				let duration_since_last_restart = Instant::now() - last_restart_time;
				if pending_restart_interval > duration_since_last_restart {
					process_tasks(
						&environment,
						&future_service_data,
						&current_set,
						block.pending_tasks().take(max_additional_sessions),
						&mut service_data,
					);
				}

				// TODO: clear recent_*
			}

			ready(())
		})
		.await;

	Ok(())
}

fn process_tasks<E, TP, KS>(
	future_environment: &Arc<Environment<E, TP, KS>>,
	future_service_data: &Arc<RwLock<ServiceData>>,
	current_set: &BTreeSet<KeyServerId>,
	new_tasks: impl Iterator<Item = BlockchainServiceTask>,
	service_data: &mut ServiceData,
) -> usize where
	E: Executor,
	TP: TransactionPool,
	KS: KeyServer,
{
	let mut added_tasks = 0;
	for new_task in new_tasks {
		let filtered_task = process_task(
			future_environment,
			future_service_data,
			current_set,
			new_task,
			service_data,
		);

		if let Some(filtered_task) = filtered_task {
			future_environment.executor.spawn(filtered_task.boxed());
		}

		added_tasks += 1;
	}

	added_tasks
}

fn process_task<E, TP, KS>(
	future_environment: &Arc<Environment<E, TP, KS>>,
	future_service_data: &Arc<RwLock<ServiceData>>,
	current_set: &BTreeSet<KeyServerId>,
	task: BlockchainServiceTask,
	service_data: &mut ServiceData,
) -> Option<impl Future<Output = ()>> where
	E: Executor,
	TP: TransactionPool,
	KS: KeyServer,
{
	match task {
		BlockchainServiceTask::Regular(ServiceTask::GenerateServerKey(key_id, requester, threshold)) => {
			if !filter_task(
				&current_set,
				&future_environment.self_id,
				&key_id,
				&mut service_data.server_key_generation_sessions,
				&mut service_data.recent_server_key_generation_sessions,
			) {
				return None;
			}

			let future_environment = future_environment.clone();
			let future_service_data = future_service_data.clone();
			Some(Either::Left(
				future_environment
					.key_server
					.generate_key(key_id, requester, threshold)
					.map(move |result| {
						future_service_data.write().server_key_generation_sessions.remove(&key_id);

						match result {
							Ok(key) => future_environment.transaction_pool.publish_generated_server_key(key_id, key),
							Err(error) if error.is_non_fatal() => {
								log_nonfatal_secret_store_error(&format!("GenerateServerKey({})", key_id), error);
							},
							Err(error) => {
								log_fatal_secret_store_error(&format!("GenerateServerKey({})", key_id), error);
								future_environment.transaction_pool.publish_server_key_generation_error(key_id);
							}
						}
					})
			))
		},
		BlockchainServiceTask::Regular(ServiceTask::RetrieveServerKey(key_id, requester)) => {
			if !filter_task(
				&current_set,
				&future_environment.self_id,
				&key_id,
				&mut service_data.server_key_retrieval_sessions,
				&mut service_data.recent_server_key_retrieval_sessions,
			) {
				return None;
			}

			let future_environment = future_environment.clone();
			let future_service_data = future_service_data.clone();
			Some(Either::Right(Either::Left(
				future_environment
					.key_server
					.restore_key_public(key_id, requester)
					.map(move |result| {
						future_service_data.write().server_key_retrieval_sessions.remove(&key_id);

						match result {
							Ok(key) => future_environment.transaction_pool.publish_retrieved_server_key(key_id, key),
							Err(error) if error.is_non_fatal() => {
								log_nonfatal_secret_store_error(&format!("RetrieveServerKey({})", key_id), error);
							},
							Err(error) => {
								log_fatal_secret_store_error(&format!("RetrieveServerKey({})", key_id), error);
								future_environment.transaction_pool.publish_server_key_retrieval_error(key_id);
							}
						}
					})
			)))
		},
		BlockchainServiceTask::Regular(
			ServiceTask::StoreDocumentKey(key_id, requester, common_point, encrypted_point),
		) => {
			if !filter_task(
				&current_set,
				&future_environment.self_id,
				&key_id,
				&mut service_data.document_key_store_sessions,
				&mut service_data.recent_document_key_store_sessions,
			) {
				return None;
			}

			let future_environment = future_environment.clone();
			let future_service_data = future_service_data.clone();
			Some(Either::Right(Either::Right(Either::Left(
				future_environment
					.key_server
					.store_document_key(key_id, requester, common_point, encrypted_point)
					.map(move |result| {
						future_service_data.write().document_key_store_sessions.remove(&key_id);

						match result {
							Ok(_) => future_environment.transaction_pool.publish_stored_document_key(key_id),
							Err(error) if error.is_non_fatal() => {
								log_nonfatal_secret_store_error(&format!("StoreDocumentKey({})", key_id), error);
							},
							Err(error) => {
								log_fatal_secret_store_error(&format!("StoreDocumentKey({})", key_id), error);
								future_environment.transaction_pool.publish_document_key_store_error(key_id);
							}
						}
					})
			))))
		},
		BlockchainServiceTask::RetrieveShadowDocumentKeyCommon(key_id, requester) => {
			if !filter_document_task(
				&current_set,
				&future_environment.self_id,
				&key_id,
				&requester,
				&mut service_data.document_key_common_retrieval_sessions,
				&mut service_data.recent_document_key_common_retrieval_sessions,
			) {
				return None;
			}

			let future_environment = future_environment.clone();
			let future_service_data = future_service_data.clone();
			Some(Either::Right(Either::Right(Either::Right(Either::Left(
				future_environment
					.key_server
					.restore_document_key_common(key_id, requester.clone())
					.map(move |result| {
						future_service_data.write().document_key_common_retrieval_sessions.remove(&(key_id, requester.clone()));

						match result {
							Ok(key_common) => future_environment.transaction_pool.publish_retrieved_document_key_common(
								key_id,
								requester,
								key_common,
							),
							Err(error) if error.is_non_fatal() => {
								log_nonfatal_secret_store_error(
									&format!("RestoreDocumentKeyCommon({}, {})", key_id, requester),
									error,
								);
							},
							Err(error) => {
								log_fatal_secret_store_error(
									&format!("RestoreDocumentKeyCommon({}, {})", key_id, requester),
									error,
								);
								future_environment.transaction_pool.publish_document_key_common_retrieval_error(key_id, requester);
							}
						}
					})
			)))))
		},
		BlockchainServiceTask::RetrieveShadowDocumentKeyPersonal(key_id, requester) => {
			if !filter_document_task(
				&current_set,
				&future_environment.self_id,
				&key_id,
				&requester,
				&mut service_data.document_key_personal_retrieval_sessions,
				&mut service_data.recent_document_key_personal_retrieval_sessions,
			) {
				return None;
			}

			let future_environment = future_environment.clone();
			let future_service_data = future_service_data.clone();
			Some(Either::Right(Either::Right(Either::Right(Either::Right(
				future_environment
					.key_server
					.restore_document_key_shadow(key_id, requester.clone())
					.map(move |result| {
						future_service_data.write().document_key_personal_retrieval_sessions.remove(&(key_id, requester.clone()));

						match result {
							Ok(key_personal) => future_environment.transaction_pool.publish_retrieved_document_key_personal(
								key_id,
								requester,
								key_personal,
							),
							Err(error) if error.is_non_fatal() => {
								log_nonfatal_secret_store_error(
									&format!("RestoreDocumentKeyPersonal({}, {})", key_id, requester),
									error,
								);
							},
							Err(error) => {
								log_fatal_secret_store_error(
									&format!("RestoreDocumentKeyPersonal({}, {})", key_id, requester),
									error,
								);
								future_environment.transaction_pool.publish_document_key_personal_retrieval_error(key_id, requester);
							}
						}
					})
			)))))
		},
		BlockchainServiceTask::Regular(ServiceTask::GenerateDocumentKey(_, _, _)) => {
			unimplemented!("GenerateDocumentKey requests are not implemented on blockchain services");
		},
		BlockchainServiceTask::Regular(ServiceTask::RetrieveDocumentKey(_, _)) => {
			unimplemented!("RetrieveDocumentKey requests are not implemented on blockchain services");
		},
		BlockchainServiceTask::Regular(ServiceTask::RetrieveShadowDocumentKey(_, _)) => {
			unimplemented!("RetrieveShadowDocumentKey requests are not implemented on blockchain services");
		},
		BlockchainServiceTask::Regular(ServiceTask::SchnorrSignMessage(_, _, _)) => {
			unimplemented!("SchnorrSignMessage requests are not implemented on blockchain services");
		},
		BlockchainServiceTask::Regular(ServiceTask::EcdsaSignMessage(_, _, _)) => {
			unimplemented!("EcdsaSignMessage requests are not implemented on blockchain services");
		},
		BlockchainServiceTask::Regular(ServiceTask::ChangeServersSet(_, _, _)) => {
			unimplemented!("ChangeServersSet requests are not implemented on blockchain services");
		},
	}
}

fn log_nonfatal_secret_store_error(request_type: &str, error: Error) {
	warn!(
		target: "secretstore",
		"{} request has nonfatally failed with: {}",
		request_type,
		error,
	);
}

fn log_fatal_secret_store_error(request_type: &str, error: Error) {
	error!(
		target: "secretstore",
		"{} request has failed with: {}",
		request_type,
		error,
	);
}

/// Returns true when session, related to `server_key_id` could be started now.
fn filter_task(
	current_set: &BTreeSet<KeyServerId>,
	self_id: &KeyServerId,
	server_key_id: &ServerKeyId,
	active_sessions: &mut HashSet<ServerKeyId>,
	recent_sessions: &mut HashSet<ServerKeyId>,
) -> bool {
	// check if task mus be procesed by another node
	if !is_processed_by_this_key_server(current_set, self_id, server_key_id) {
		return false;
	}
	// check if task has been completed recently
	if !recent_sessions.insert(*server_key_id) {
		return false;
	}
	// check if task is currently processed
	if !active_sessions.insert(*server_key_id) {
		return false;
	}

	true
}

/// Returns true when session, related to both `server_key_id` and `requester` could be started now.
fn filter_document_task(
	current_set: &BTreeSet<KeyServerId>,
	self_id: &KeyServerId,
	server_key_id: &ServerKeyId,
	requester: &Requester,
	active_sessions: &mut HashSet<(ServerKeyId, Requester)>,
	recent_sessions: &mut HashSet<(ServerKeyId, Requester)>,
) -> bool {
	// check if task mus be procesed by another node
	if !is_processed_by_this_key_server(current_set, self_id, server_key_id) {
		return false;
	}
	// check if task has been completed recently
	if !recent_sessions.insert((*server_key_id, requester.clone())) {
		return false;
	}
	// check if task is currently processed
	if !active_sessions.insert((*server_key_id, requester.clone())) {
		return false;
	}

	true
}

/// Returns true when session, related to `server_key_id` must be started by this node.
fn is_processed_by_this_key_server(
	current_set: &BTreeSet<KeyServerId>,
	self_id: &KeyServerId,
	server_key_id: &ServerKeyId,
) -> bool {
	let total_servers_count = current_set.len();
	match total_servers_count {
		0 => return false,
		1 => return true,
		_ => (),
	}

	let this_server_index = match current_set.iter().enumerate().find(|&(_, s)| s == self_id) {
		Some((index, _)) => index,
		None => return false,
	};

	let server_key_id_value: U256 = server_key_id.into_uint();
	let range_interval = U256::max_value() / total_servers_count;
	let range_begin = (range_interval + 1) * this_server_index as u32;
	let range_end = range_begin.saturating_add(range_interval);

	server_key_id_value >= range_begin && server_key_id_value <= range_end
}

impl ServiceData {
	/// Return number of active sessions started by this service.
	fn active_sessions(&self) -> usize {
		self.server_key_generation_sessions.len()
			+ self.server_key_retrieval_sessions.len()
	}
}
