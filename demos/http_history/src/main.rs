/*
cargo run -p burpsuite_kit_http_history
*/

use std::env;
use std::error;
use std::fs::File;
use std::io::{self, BufReader, Cursor};
use std::str;

use base64::decode as base64_decode;
use burpsuite_kit::http_history::items::{ItemParseError, Items};
use http1_spec::{
    head_parser::{HeadParseConfig, HeadParseOutput, HeadParser},
    request_head_parser::RequestHeadParser,
    response_head_parser::ResponseHeadParser,
};
use serde_json::Value;

fn main() -> Result<(), Box<dyn error::Error>> {
    let path = env::args().nth(1).unwrap_or_else(|| {
        "tests/http_history_files/burpsuite_community_v2020.12.1.xml".to_owned()
    });
    let file = File::open(path)?;
    let buf_reader = BufReader::new(file);
    let items = Items::from_reader(buf_reader).map_err(|err| err.to_string())?;

    let items: Vec<_> = items
        .filter_map(|item| {
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
        let req_bytes = base64_decode(&item.request.1)?;
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
            HeadParseOutput::Partial(_) => return Err("req partial".to_owned().into()),
        };
        let req_body_slice = &req_buf_reader.into_inner().into_inner()[n..];
        let req_body_str = str::from_utf8(req_body_slice)?;

        println!("req_headers {:?}", req_head_parser.get_headers());
        println!("req_body_str {}", req_body_str);

        //
        let res_bytes = base64_decode(&item.response.1)?;
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
        println!("res_headers {:?}", res_headers);

        let res_body_slice = &res_buf_reader.into_inner().into_inner()[n..];
        match serde_json::from_slice::<Value>(res_body_slice) {
            Ok(res_body) => {
                println!("res_body {}", res_body);
            }
            Err(err) => {
                eprintln!("res_body parse err {:?}", err);
            }
        }
    }

    Ok(())
}
