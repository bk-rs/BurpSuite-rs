/*
RUST_LOG=debug cargo run -p burpsuite-kit-demo --bin burpsuite_kit_http_history
*/

use std::{
    env, error,
    fs::File,
    io::{self, BufReader, Cursor},
    path::PathBuf,
    str,
};

use base64::decode as base64_decode;
use burpsuite_kit::http_history::items::{ItemParseError, Items};
use http1_spec::{
    head_parser::{HeadParseConfig, HeadParseOutput, HeadParser},
    request_head_parser::RequestHeadParser,
    response_head_parser::ResponseHeadParser,
};
use log::{debug, error};
use serde_json::Value;

fn main() -> Result<(), Box<dyn error::Error>> {
    pretty_env_logger::init();

    let path = env::args().nth(1).unwrap_or_else(|| {
        let path = if let Ok(manifest_dir) = env::var("CARGO_MANIFEST_DIR") {
            PathBuf::from(&manifest_dir)
        } else {
            PathBuf::new()
        };

        path.join("../tests/http_history_files/burpsuite_community_v2020.12.1.xml")
            .to_str()
            .unwrap()
            .to_owned()
    });
    let file = File::open(path)?;
    let buf_reader = BufReader::new(file);
    let items = Items::from_reader(buf_reader)?;

    let items: Vec<_> = items
        .filter_map(|item| {
            if item.is_err() {
                error!("{:?}", item)
            }

            item.and_then(|item| {
                if item.status.is_success() {
                    Ok(item)
                } else {
                    Err(ItemParseError::XmlError(
                        io::Error::new(io::ErrorKind::Other, "").into(),
                    ))
                }
            })
            .ok()
        })
        .collect();

    for item in items.iter() {
        let req_bytes = if item.request.0.base64 {
            base64_decode(&item.request.1)?
        } else {
            item.request.1.to_owned()
        };
        let mut req_buf_reader = BufReader::new(Cursor::new(req_bytes));
        let mut req_head_parse_config = HeadParseConfig::default();
        req_head_parse_config
            .set_uri_max_len(1024)
            .set_header_max_len(2048);
        let mut req_head_parser = RequestHeadParser::with_config(req_head_parse_config);
        let req_head_parser_output = req_head_parser
            .parse(&mut req_buf_reader)
            .map_err(|err| err.to_string())?;
        let n = match req_head_parser_output {
            HeadParseOutput::Completed(n) => n,
            HeadParseOutput::Partial(_) => {
                error!("req partial, item {:?}", item);
                return Err("req partial".to_owned().into());
            }
        };
        let req_body_slice = &req_buf_reader.into_inner().into_inner()[n..];
        let req_body_str = str::from_utf8(req_body_slice)?;

        debug!("req_headers {:?}", req_head_parser.get_headers());
        debug!("req_body_str {}", req_body_str);

        //
        let res_bytes = if item.response.0.base64 {
            base64_decode(&item.response.1)?
        } else {
            item.response.1.to_owned()
        };
        let mut res_buf_reader = BufReader::new(Cursor::new(res_bytes));
        let mut res_head_parse_config = HeadParseConfig::default();
        res_head_parse_config.set_header_max_len(2048);
        let mut res_head_parser = ResponseHeadParser::with_config(res_head_parse_config);
        let res_head_parser_output = res_head_parser
            .parse(&mut res_buf_reader)
            .map_err(|err| err.to_string())?;
        let n = match res_head_parser_output {
            HeadParseOutput::Completed(n) => n,
            HeadParseOutput::Partial(_) => return Err("req partial".to_owned().into()),
        };
        let res_headers = res_head_parser.get_headers();
        debug!("res_headers {:?}", res_headers);

        let res_body_slice = &res_buf_reader.into_inner().into_inner()[n..];
        if let Some(res_content_type) = res_headers.get("content-type") {
            if res_content_type == "application/json"
                || res_content_type == "application/json; charset=utf-8"
            {
                let res_body = serde_json::from_slice::<Value>(res_body_slice)?;
                debug!("res_body {}", res_body);
            }
        }
    }

    Ok(())
}
