//! fridgep0t: a low-interaction decoy for supermarket refrigeration controllers.
//!
//! It imitates one of six refrigeration supervisors (Danfoss AK-SM 800A and AK-SC
//! 355, Dixell/Copeland XWEB EVO, Carel pCOWeb, Eliwell TelevisGo, RDM Data
//! Manager), logs who connects,
//! what they try and which public exploits they use, and never does anything
//! real. Every deployment generates its own identity (store name, MAC, hostname,
//! firmware, certificate subjects) so instances cannot be catalogued together.

pub mod aksc;
pub mod carel;
pub mod config;
pub mod danfoss;
pub mod dixell;
pub mod eliwell;
pub mod http;
pub mod identity;
pub mod logging;
pub mod modbus;
pub mod rdm;
pub mod server;
pub mod state;
pub mod tls;
pub mod util;
