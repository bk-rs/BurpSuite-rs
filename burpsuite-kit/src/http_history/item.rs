use std::{
    collections::HashSet,
    convert::TryFrom,
    iter::Iterator,
    str::{self, FromStr as _},
};

use chrono::NaiveDateTime;
use http::{uri::Scheme, Method, StatusCode};
use once_cell::sync::Lazy;
use strum::{Display, EnumIter, EnumString, IntoEnumIterator as _};

#[derive(Clone, Debug)]
pub struct Item {
    pub time: NaiveDateTime,
    pub url: String,
    pub host: (ItemHostAttr, String),
    pub port: u16,
    pub protocol: Scheme,
    pub method: Method,
    pub path: String,
    pub extension: Option<String>,
    pub request: (ItemRequestAttr, Vec<u8>),
    pub status: StatusCode,
    pub response_length: u32,
    pub mimetype: String,
    pub response: (ItemResponseAttr, Vec<u8>),
    pub comment: Option<String>,
}

impl Default for Item {
    fn default() -> Self {
        Self {
            time: NaiveDateTime::from_timestamp(0, 0),
            url: Default::default(),
            host: Default::default(),
            port: Default::default(),
            protocol: Scheme::HTTP,
            method: Default::default(),
            path: Default::default(),
            extension: Default::default(),
            request: Default::default(),
            status: Default::default(),
            response_length: Default::default(),
            mimetype: Default::default(),
            response: Default::default(),
            comment: Default::default(),
        }
    }
}

#[derive(Default, Clone, Debug)]
pub struct ItemHostAttr {
    pub ip: Vec<u8>,
}

#[derive(Default, Clone, Debug)]
pub struct ItemRequestAttr {
    pub base64: bool,
}

#[derive(Default, Clone, Debug)]
pub struct ItemResponseAttr {
    pub base64: bool,
}

//
//
//
#[derive(PartialEq, Eq, Hash, Debug, Clone, Display, EnumString, EnumIter)]
#[strum(serialize_all = "snake_case")]
pub enum Tag {
    Time,
    Url,
    Host,
    Port,
    Protocol,
    Method,
    Path,
    Extension,
    Request,
    Status,
    #[strum(serialize = "responselength")]
    ResponseLength,
    Mimetype,
    Response,
    Comment,
}

impl TryFrom<&[u8]> for Tag {
    type Error = String;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_str(str::from_utf8(value).map_err(|err| err.to_string())?)
            .map_err(|err| err.to_string())
    }
}

pub(super) static TAG_SET: Lazy<HashSet<Tag>> = Lazy::new(|| Tag::iter().collect());
