//! Modbus TCP: the fake holding registers behind the optional `MODBUS_PORT`.
//!
//! Function codes 3/4 (read), 6/16 (write) and 43/14 (device identification)
//! are answered from `Registers`; anything else gets an exception. Every frame
//! is logged, and a write to a defrost register is flagged as such.

use crate::config::Persona;
use crate::fields;
use crate::server::App;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Run one Modbus TCP connection, whole, under `conn_deadline`.
pub async fn serve_modbus(app: Arc<App>, stream: TcpStream, peer: SocketAddr) {
    let deadline = app.cfg.conn_deadline;
    let _ = tokio::time::timeout(deadline, modbus_loop(app, stream, peer)).await;
}

async fn modbus_loop(app: Arc<App>, mut stream: TcpStream, peer: SocketAddr) {
    app.log.log("modbus", peer, "connect", fields! {});
    loop {
        let mut header = [0u8; 7];
        if !read_exact_idle(&app, &mut stream, &mut header).await {
            return;
        }
        let tid = u16::from_be_bytes([header[0], header[1]]);
        let proto = u16::from_be_bytes([header[2], header[3]]);
        let length = u16::from_be_bytes([header[4], header[5]]);
        let unit = header[6];
        if proto != 0 || !(2..=254).contains(&length) {
            app.log.log(
                "modbus",
                peer,
                "malformed",
                fields! { "header_hex" => hex(&header) },
            );
            return;
        }
        // The PDU read is bounded too: a header with no PDU must not hold a slot.
        let mut pdu = vec![0u8; (length - 1) as usize];
        if !read_exact_idle(&app, &mut stream, &mut pdu).await {
            return;
        }
        let reply = handle_pdu(&app, peer, unit, &pdu);
        let mut frame = Vec::with_capacity(7 + reply.len());
        frame.extend_from_slice(&tid.to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes());
        frame.extend_from_slice(&((reply.len() + 1) as u16).to_be_bytes());
        frame.push(unit);
        frame.extend_from_slice(&reply);
        if stream.write_all(&frame).await.is_err() {
            return;
        }
    }
}

/// `read_exact` under the idle timeout; false on timeout, EOF or error.
async fn read_exact_idle(app: &App, stream: &mut TcpStream, buf: &mut [u8]) -> bool {
    matches!(
        tokio::time::timeout(app.cfg.socket_timeout, stream.read_exact(buf)).await,
        Ok(Ok(_))
    )
}

fn modbus_exc(fc: u8, code: u8) -> Vec<u8> {
    vec![fc | 0x80, code]
}

fn handle_pdu(app: &Arc<App>, peer: SocketAddr, unit: u8, pdu: &[u8]) -> Vec<u8> {
    let fc = pdu[0];
    match fc {
        3 | 4 if pdu.len() == 5 => {
            let start = u16::from_be_bytes([pdu[1], pdu[2]]);
            let count = u16::from_be_bytes([pdu[3], pdu[4]]);
            if !(1..=125).contains(&count) {
                return modbus_exc(fc, 3);
            }
            app.log.log(
                "modbus",
                peer,
                "read",
                fields! { "unit" => unit, "fc" => fc, "start" => start, "count" => count },
            );
            if !app.regs.mapped(start, count) {
                return modbus_exc(fc, 2);
            }
            let values = app.regs.read(start, count);
            let mut out = vec![fc, (count * 2) as u8];
            for v in values {
                out.extend_from_slice(&v.to_be_bytes());
            }
            out
        }
        6 if pdu.len() == 5 => {
            let addr = u16::from_be_bytes([pdu[1], pdu[2]]);
            let value = u16::from_be_bytes([pdu[3], pdu[4]]);
            app.log.log(
                "modbus",
                peer,
                "write",
                fields! {
                    "unit" => unit, "fc" => fc, "start" => addr, "values" => [value],
                    "defrost" => (200..208).contains(&addr) && value != 0,
                },
            );
            if !app.regs.mapped(addr, 1) {
                return modbus_exc(fc, 2);
            }
            app.regs.write(addr, &[value]);
            pdu.to_vec()
        }
        16 if pdu.len() >= 6 => {
            let start = u16::from_be_bytes([pdu[1], pdu[2]]);
            let count = u16::from_be_bytes([pdu[3], pdu[4]]);
            let nbytes = pdu[5] as usize;
            if !(1..=123).contains(&count) || nbytes != count as usize * 2 || pdu.len() != 6 + nbytes {
                return modbus_exc(fc, 3);
            }
            let values: Vec<u16> = (0..count as usize)
                .map(|i| u16::from_be_bytes([pdu[6 + i * 2], pdu[7 + i * 2]]))
                .collect();
            let defrost = values.iter().enumerate().any(|(i, &v)| {
                let a = start.wrapping_add(i as u16);
                (200..208).contains(&a) && v != 0
            });
            app.log.log("modbus", peer, "write", fields! {
                "unit" => unit, "fc" => fc, "start" => start, "values" => values.clone(), "defrost" => defrost,
            });
            if !app.regs.mapped(start, count) {
                return modbus_exc(fc, 2);
            }
            app.regs.write(start, &values);
            pdu[..5].to_vec()
        }
        43 if pdu.len() >= 2 && pdu[1] == 0x0E => {
            app.log
                .log("modbus", peer, "device_id", fields! { "unit" => unit });
            device_id_response(app)
        }
        _ => {
            app.log.log(
                "modbus",
                peer,
                "unsupported",
                fields! {
                    "unit" => unit, "fc" => fc, "pdu_hex" => hex(&pdu[..pdu.len().min(64)]),
                },
            );
            modbus_exc(fc, 1)
        }
    }
}

fn device_id_response(app: &Arc<App>) -> Vec<u8> {
    let (vendor, product) = match app.cfg.persona {
        Persona::Danfoss => ("Danfoss", "AK-SM 800A"),
        Persona::Dixell => ("Dixell", "XWEB EVO"),
        Persona::Aksc355 => ("Danfoss", "AK-SC 355"),
        Persona::Carel => ("Carel", "pCOWeb"),
        Persona::Eliwell => ("Eliwell", "TelevisGo"),
        Persona::Rdm => ("RDM", "Data Manager"),
    };
    let objects = [vendor.to_string(), product.to_string(), app.id.firmware.clone()];
    let mut out = vec![0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, objects.len() as u8];
    for (id, text) in objects.iter().enumerate() {
        let raw = text.as_bytes();
        out.push(id as u8);
        out.push(raw.len() as u8);
        out.extend_from_slice(raw);
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}
