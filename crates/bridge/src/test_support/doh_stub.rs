//! A DoH querier that resolves one hostname to one IPv4, so a test drives a
//! real bootstrap leg with no OS resolver or network.

use std::net::IpAddr;

use crate::dns::bootstrap::DohQuerier;
use crate::dns::forwarder::UpstreamCause;

/// Resolves exactly `host` to `ip`: proves a start resolves via DoH (not the
/// OS) and hands the result downstream.
pub(crate) struct WiringStubQuerier {
    pub(crate) host: String,
    pub(crate) ip: IpAddr,
}

#[async_trait::async_trait]
impl DohQuerier for WiringStubQuerier {
    async fn query(&self, _server: IpAddr, wire: &[u8]) -> Result<Vec<u8>, UpstreamCause> {
        crate::dns::forwarder::answered_or_servfail(wire, || {
            use hickory_proto::op::{Message, MessageType, OpCode, Query};
            use hickory_proto::rr::rdata::A;
            use hickory_proto::rr::{Name, RData, Record, RecordType};
            // Only answer the A query (port-free: the stub keys on hostname).
            let q = Message::from_vec(wire).ok()?;
            let question = q.queries.first()?;
            if question.query_type() != RecordType::A {
                return None; // force the resolver onto the A path (IPv4-preferred).
            }
            let IpAddr::V4(v4) = self.ip else { return None };
            let n = Name::from_ascii(format!("{}.", self.host)).ok()?;
            let mut reply = Message::new(0, MessageType::Response, OpCode::Query);
            reply.add_query(Query::query(n.clone(), RecordType::A));
            reply.add_answer(Record::from_rdata(n, 60, RData::A(A(v4))));
            reply.to_vec().ok()
        })
    }
}

/// A [`WiringStubQuerier`] that records how the redaction registry renders its
/// hostname at each query: the registry's state at the run's first use of the
/// configured address, which a log line cannot show deterministically.
pub(crate) struct ArmedProbeQuerier {
    pub(crate) inner: WiringStubQuerier,
    /// `util::redact::redact_str(host)` at every query, in order.
    pub(crate) host_as_rendered: std::sync::Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl DohQuerier for ArmedProbeQuerier {
    async fn query(&self, server: IpAddr, wire: &[u8]) -> Result<Vec<u8>, UpstreamCause> {
        self.host_as_rendered
            .lock()
            .unwrap()
            .push(util::redact::redact_str(&self.inner.host).into_owned());
        self.inner.query(server, wire).await
    }
}
