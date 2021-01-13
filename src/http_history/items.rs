use std::collections::HashSet;
use std::convert::TryFrom;
use std::fmt;
use std::io::BufRead;
use std::iter::Iterator;
use std::num::ParseIntError;
use std::str::{self, ParseBoolError};

use chrono::NaiveDateTime;
use http::{
    uri::{InvalidUri, Scheme},
    Method, StatusCode,
};
use quick_xml::{
    events::{attributes::Attribute, Event},
    Error, Reader,
};

use super::item::{Item, Tag as ItemTag, TAG_SET as ITEM_TAG_SET};

pub struct Items<R>
where
    R: BufRead,
{
    pub attr: ItemsAttr,

    reader: Reader<R>,
    buf: Vec<u8>,
    state: State,
    item: Item,
    processed_item_tags: HashSet<ItemTag>,
    is_eof: bool,
}

pub struct ItemsAttr {
    pub burp_version: String,
    pub export_time: NaiveDateTime,
}

#[derive(PartialEq, Debug)]
enum State {
    Idle,
    WaitTag,
    WaitTagValue(ItemTag),
}

#[derive(Debug)]
pub enum ItemsParseError {
    XmlError(Error),
    UnknownTag(Vec<u8>),
    UnexpectedEof,
    AttrMissing(String),
    AttrInvalid(String, String),
}

impl fmt::Display for ItemsParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::XmlError(err) => write!(f, "XmlError {:?}", err),
            Self::UnknownTag(name) => write!(f, "UnknownTag {:?}", name),
            Self::UnexpectedEof => write!(f, "Unexpected"),
            Self::AttrMissing(attr) => write!(f, "AttrMissing {}", attr),
            Self::AttrInvalid(attr, msg) => write!(f, "AttrInvalid {} {}", attr, msg),
        }
    }
}

impl<R> Items<R>
where
    R: BufRead,
{
    pub fn from_reader(reader: R) -> Result<Self, ItemsParseError> {
        let mut reader = Reader::from_reader(reader);

        let mut buf = Vec::new();
        let attr = loop {
            match reader.read_event(&mut buf) {
                Ok(Event::Start(e)) => match e.name() {
                    b"items" => {
                        let attrs: Vec<Attribute<'_>> =
                            e.attributes().map(|ret| ret.ok()).flatten().collect();

                        let burp_version = attrs
                            .iter()
                            .find(|a| a.key == b"burpVersion")
                            .map(|x| x.value.to_owned())
                            .ok_or_else(|| {
                                ItemsParseError::AttrMissing("burpVersion".to_owned())
                            })?;

                        let burp_version = str::from_utf8(burp_version.as_ref())
                            .map(|x| x.to_owned())
                            .map_err(|err| {
                                ItemsParseError::AttrInvalid(
                                    "burpVersion".to_owned(),
                                    err.to_string(),
                                )
                            })?;

                        let export_time = attrs
                            .iter()
                            .find(|a| a.key == b"exportTime")
                            .map(|x| x.value.to_owned())
                            .ok_or_else(|| ItemsParseError::AttrMissing("exportTime".to_owned()))?;

                        let export_time = NaiveDateTime::parse_from_str(
                            str::from_utf8(export_time.as_ref()).map_err(|err| {
                                ItemsParseError::AttrInvalid(
                                    "exportTime".to_owned(),
                                    err.to_string(),
                                )
                            })?,
                            "%a %b %d %T %Z %Y",
                        )
                        .map_err(|err| {
                            ItemsParseError::AttrInvalid("exportTime".to_owned(), err.to_string())
                        })?;

                        break ItemsAttr {
                            burp_version,
                            export_time,
                        };
                    }
                    _ => return Err(ItemsParseError::UnknownTag(e.name().to_owned())),
                },
                Ok(Event::Text(_)) => {}
                Err(err) => return Err(ItemsParseError::XmlError(err)),
                Ok(Event::Eof) => return Err(ItemsParseError::UnexpectedEof),
                _ => {}
            }

            buf.clear();
        };

        Ok(Self {
            attr,
            reader,
            buf,
            state: State::Idle,
            item: Default::default(),
            processed_item_tags: HashSet::new(),
            is_eof: false,
        })
    }
}

#[derive(Debug)]
pub enum ItemParseError {
    XmlError(Error),
    UnknownTag(Vec<u8>),
    UnexpectedEof,
    StateMismatch(String),
    SomeTagsMissing(HashSet<ItemTag>),
    DuplicateTag(ItemTag),
    TagAttrMissing(ItemTag, String),
    TagAttrInvalid(ItemTag, String, String),
    TagValueMissing(ItemTag),
    TagValueInvalid(ItemTag, String),
}

impl fmt::Display for ItemParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::XmlError(err) => write!(f, "XmlError {:?}", err),
            Self::UnknownTag(name) => write!(f, "UnknownTag {:?}", name),
            Self::UnexpectedEof => write!(f, "Unexpected"),
            Self::StateMismatch(msg) => write!(f, "StateMismatch {}", msg),
            Self::SomeTagsMissing(tags) => write!(f, "SomeTagsMissing {:?}", tags),
            Self::DuplicateTag(tag) => write!(f, "DuplicateTag {:?}", tag),
            Self::TagAttrMissing(tag, attr) => write!(f, "TagAttrMissing {:?} {}", tag, attr),
            Self::TagAttrInvalid(tag, attr, msg) => {
                write!(f, "TagAttrInvalid {:?} {} {}", tag, attr, msg)
            }
            Self::TagValueMissing(tag) => write!(f, "TagValueMissing {:?}", tag),
            Self::TagValueInvalid(tag, msg) => write!(f, "TagValueInvalid {:?} {}", tag, msg),
        }
    }
}

impl<R> Items<R>
where
    R: BufRead,
{
    fn item(&mut self) -> Result<Item, ItemParseError> {
        loop {
            match self.reader.read_event(&mut self.buf) {
                Ok(Event::Start(e)) => match e.name() {
                    b"item" => {
                        if State::Idle != self.state {
                            return Err(ItemParseError::StateMismatch(format!(
                                "expect {:?} but current {:?}",
                                State::Idle,
                                self.state
                            )));
                        }

                        self.state = State::WaitTag;
                    }
                    _ => {
                        if let Ok(tag) = ItemTag::try_from(e.name()) {
                            match self.state {
                                State::Idle => {
                                    return Err(ItemParseError::StateMismatch(format!(
                                        "expect not {:?}",
                                        self.state
                                    )));
                                }
                                State::WaitTag => {
                                    if self.processed_item_tags.contains(&tag) {
                                        return Err(ItemParseError::DuplicateTag(tag));
                                    }

                                    match tag {
                                        ItemTag::Host => {
                                            let attrs: Vec<Attribute<'_>> = e
                                                .attributes()
                                                .map(|ret| ret.ok())
                                                .flatten()
                                                .collect();

                                            let ip = attrs
                                                .iter()
                                                .find(|a| a.key == b"ip")
                                                .map(|x| x.value.to_owned())
                                                .ok_or_else(|| {
                                                    ItemParseError::TagAttrMissing(
                                                        tag.to_owned(),
                                                        "ip".to_owned(),
                                                    )
                                                })?;

                                            self.item.host.0.ip = ip.into_owned();
                                        }
                                        ItemTag::Request => {
                                            let attrs: Vec<Attribute<'_>> = e
                                                .attributes()
                                                .map(|ret| ret.ok())
                                                .flatten()
                                                .collect();

                                            let base64 = attrs
                                                .iter()
                                                .find(|a| a.key == b"base64")
                                                .map(|x| x.value.to_owned())
                                                .ok_or_else(|| {
                                                    ItemParseError::TagAttrMissing(
                                                        tag.to_owned(),
                                                        "base64".to_owned(),
                                                    )
                                                })?;

                                            let base64 =
                                                str::from_utf8(base64.as_ref()).map_err(|err| {
                                                    ItemParseError::TagAttrInvalid(
                                                        tag.to_owned(),
                                                        "base64".to_owned(),
                                                        err.to_string(),
                                                    )
                                                })?;

                                            let base64: bool =
                                                base64.parse().map_err(|err: ParseBoolError| {
                                                    ItemParseError::TagAttrInvalid(
                                                        tag.to_owned(),
                                                        "base64".to_owned(),
                                                        err.to_string(),
                                                    )
                                                })?;

                                            self.item.request.0.base64 = base64;
                                        }
                                        ItemTag::Response => {
                                            let attrs: Vec<Attribute<'_>> = e
                                                .attributes()
                                                .map(|ret| ret.ok())
                                                .flatten()
                                                .collect();

                                            let base64 = attrs
                                                .iter()
                                                .find(|a| a.key == b"base64")
                                                .map(|x| x.value.to_owned())
                                                .ok_or_else(|| {
                                                    ItemParseError::TagAttrMissing(
                                                        tag.to_owned(),
                                                        "base64".to_owned(),
                                                    )
                                                })?;

                                            let base64 =
                                                str::from_utf8(base64.as_ref()).map_err(|err| {
                                                    ItemParseError::TagAttrInvalid(
                                                        tag.to_owned(),
                                                        "base64".to_owned(),
                                                        err.to_string(),
                                                    )
                                                })?;

                                            let base64: bool =
                                                base64.parse().map_err(|err: ParseBoolError| {
                                                    ItemParseError::TagAttrInvalid(
                                                        tag.to_owned(),
                                                        "base64".to_owned(),
                                                        err.to_string(),
                                                    )
                                                })?;

                                            self.item.response.0.base64 = base64;
                                        }
                                        _ => {}
                                    }

                                    self.state = State::WaitTagValue(tag)
                                }
                                State::WaitTagValue(_) => {
                                    return Err(ItemParseError::StateMismatch(format!(
                                        "expect not {:?}",
                                        self.state
                                    )));
                                }
                            }
                        } else {
                            return Err(ItemParseError::UnknownTag(e.name().to_owned()));
                        }
                    }
                },
                Ok(Event::End(e)) => match e.name() {
                    b"items" => {}
                    b"item" => {
                        let unprocessed_item_tags = ITEM_TAG_SET
                            .difference(&self.processed_item_tags)
                            .collect::<HashSet<_>>();

                        if !unprocessed_item_tags.is_empty() {
                            return Err(ItemParseError::SomeTagsMissing(
                                unprocessed_item_tags
                                    .into_iter()
                                    .map(|x| x.to_owned())
                                    .collect(),
                            ));
                        }

                        self.state = State::Idle;
                        self.processed_item_tags.clear();

                        return Ok(self.item.to_owned());
                    }
                    _ => {
                        if let Ok(tag) = ItemTag::try_from(e.name()) {
                            match self.state {
                                State::Idle => {
                                    return Err(ItemParseError::StateMismatch(format!(
                                        "expect not {:?}",
                                        self.state
                                    )));
                                }
                                State::WaitTag => {
                                    return Err(ItemParseError::StateMismatch(format!(
                                        "expect not {:?}",
                                        self.state
                                    )));
                                }
                                State::WaitTagValue(_) => {
                                    if self.processed_item_tags.contains(&tag) {
                                        self.state = State::WaitTag;
                                    } else {
                                        return Err(ItemParseError::TagValueMissing(tag));
                                    }
                                }
                            }
                        } else {
                            return Err(ItemParseError::UnknownTag(e.name().to_owned()));
                        }
                    }
                },
                Ok(Event::Text(e)) => match self.state {
                    State::Idle => {}
                    State::WaitTag => {}
                    State::WaitTagValue(ref tag) => match e.unescape_and_decode(&self.reader) {
                        Ok(text) => match tag {
                            ItemTag::Time => {
                                let time = NaiveDateTime::parse_from_str(
                                    str::from_utf8(text.as_ref()).map_err(|err| {
                                        ItemParseError::TagValueInvalid(
                                            tag.to_owned(),
                                            err.to_string(),
                                        )
                                    })?,
                                    "%a %b %d %T %Z %Y",
                                )
                                .map_err(|err| {
                                    ItemParseError::TagValueInvalid(tag.to_owned(), err.to_string())
                                })?;

                                self.item.time = time;

                                self.processed_item_tags.insert(tag.to_owned());
                            }
                            ItemTag::Host => {
                                self.item.host.1 = text;

                                self.processed_item_tags.insert(tag.to_owned());
                            }
                            ItemTag::Port => {
                                let port: u16 = text.parse().map_err(|err: ParseIntError| {
                                    ItemParseError::TagValueInvalid(tag.to_owned(), err.to_string())
                                })?;

                                self.item.port = port;

                                self.processed_item_tags.insert(tag.to_owned());
                            }
                            ItemTag::Protocol => {
                                let protocol: Scheme =
                                    text.parse().map_err(|err: InvalidUri| {
                                        ItemParseError::TagValueInvalid(
                                            tag.to_owned(),
                                            err.to_string(),
                                        )
                                    })?;

                                self.item.protocol = protocol;

                                self.processed_item_tags.insert(tag.to_owned());
                            }
                            ItemTag::Extension => {
                                self.item.extension =
                                    if text == "null" { None } else { Some(text) };

                                self.processed_item_tags.insert(tag.to_owned());
                            }
                            ItemTag::Status => {
                                let status =
                                    StatusCode::from_bytes(text.as_bytes()).map_err(|err| {
                                        ItemParseError::TagValueInvalid(
                                            tag.to_owned(),
                                            err.to_string(),
                                        )
                                    })?;

                                self.item.status = status;

                                self.processed_item_tags.insert(tag.to_owned());
                            }
                            ItemTag::ResponseLength => {
                                let response_length: u32 =
                                    text.parse().map_err(|err: ParseIntError| {
                                        ItemParseError::TagValueInvalid(
                                            tag.to_owned(),
                                            err.to_string(),
                                        )
                                    })?;

                                self.item.response_length = response_length;

                                self.processed_item_tags.insert(tag.to_owned());
                            }
                            ItemTag::Mimetype => {
                                self.item.mimetype = text;

                                self.processed_item_tags.insert(tag.to_owned());
                            }
                            ItemTag::Comment => {
                                self.item.comment = if text.is_empty() { None } else { Some(text) };

                                self.processed_item_tags.insert(tag.to_owned());
                            }
                            _ => {}
                        },
                        Err(err) => return Err(ItemParseError::XmlError(err)),
                    },
                },
                Ok(Event::CData(e)) => match self.state {
                    State::Idle => {}
                    State::WaitTag => {}
                    State::WaitTagValue(ref tag) => match tag {
                        ItemTag::Request | ItemTag::Response => match e.unescaped() {
                            Ok(bytes) => match tag {
                                ItemTag::Request => {
                                    self.item.request.1 = bytes.into_owned();

                                    self.processed_item_tags.insert(tag.to_owned());
                                }
                                ItemTag::Response => {
                                    self.item.response.1 = bytes.into_owned();

                                    self.processed_item_tags.insert(tag.to_owned());
                                }
                                _ => {}
                            },
                            Err(err) => return Err(ItemParseError::XmlError(err)),
                        },
                        _ => match e.unescape_and_decode(&self.reader) {
                            Ok(text) => match tag {
                                ItemTag::Url => {
                                    self.item.url = text;

                                    self.processed_item_tags.insert(tag.to_owned());
                                }
                                ItemTag::Method => {
                                    let method =
                                        Method::from_bytes(text.as_bytes()).map_err(|err| {
                                            ItemParseError::TagValueInvalid(
                                                tag.to_owned(),
                                                err.to_string(),
                                            )
                                        })?;

                                    self.item.method = method;

                                    self.processed_item_tags.insert(tag.to_owned());
                                }
                                ItemTag::Path => {
                                    self.item.path = text;
                                    self.processed_item_tags.insert(tag.to_owned());
                                }
                                _ => {}
                            },
                            Err(err) => return Err(ItemParseError::XmlError(err)),
                        },
                    },
                },
                Err(err) => return Err(ItemParseError::XmlError(err)),
                Ok(Event::Eof) => return Err(ItemParseError::UnexpectedEof),
                _ => {}
            }

            self.buf.clear();
        }
    }
}

impl<R> Iterator for Items<R>
where
    R: BufRead,
{
    type Item = Result<Item, ItemParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.item() {
            Ok(item) => Some(Ok(item)),
            Err(err) => match err {
                ItemParseError::UnexpectedEof => {
                    if self.state == State::Idle {
                        None
                    } else {
                        if self.is_eof {
                            return None;
                        }
                        self.is_eof = true;
                        Some(Err(err))
                    }
                }
                _ => Some(Err(err)),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;
    use std::io::BufReader;

    use chrono::NaiveDate;

    #[test]
    fn test_v_1_7_36() -> Result<(), String> {
        let file = File::open("tests/http_history_files/burpsuite_community_v1.7.36.xml").unwrap();
        let buf_reader = BufReader::new(file);
        let mut items = Items::from_reader(buf_reader).map_err(|err| err.to_string())?;

        assert_eq!(items.attr.burp_version, "1.7.36");
        assert_eq!(
            items.attr.export_time,
            NaiveDate::from_ymd(2021, 1, 6).and_hms(11, 27, 54)
        );

        match items.next() {
            Some(Ok(item)) => {
                assert_eq!(
                    item.time,
                    NaiveDate::from_ymd(2021, 1, 6).and_hms(11, 26, 17)
                );
                assert_eq!(item.url, "http://httpbin.org/get?foo=bar");
                assert_eq!(item.host.0.ip, b"184.72.216.47");
                assert_eq!(item.host.1, "httpbin.org");
                assert_eq!(item.port, 80);
                assert_eq!(item.protocol, Scheme::HTTP);
                assert_eq!(item.method, Method::GET);
                assert_eq!(item.path, "/get?foo=bar");
                assert_eq!(item.extension, None);
                assert_eq!(item.request.0.base64, true);
                assert_eq!(item.request.1.starts_with(b"R0VUIC"), true);
                assert_eq!(item.request.1.ends_with(b"UNCg0K"), true);
                assert_eq!(item.status, 200);
                assert_eq!(item.response_length, 508);
                assert_eq!(item.mimetype, "JSON");
                assert_eq!(item.response.0.base64, true);
                assert_eq!(item.response.1.starts_with(b"SFRUUC"), true);
                assert_eq!(item.response.1.ends_with(b"p9Cg=="), true);
                assert_eq!(item.comment, None);
            }
            Some(Err(err)) => {
                eprintln!("{}", err);
                assert!(false, err);
            }
            None => assert!(false),
        }

        match items.next() {
            Some(Ok(item)) => {
                assert_eq!(
                    item.time,
                    NaiveDate::from_ymd(2021, 1, 6).and_hms(11, 27, 9)
                );
                assert_eq!(item.url, "https://httpbin.org/post");
                assert_eq!(item.host.0.ip, b"54.164.234.192");
                assert_eq!(item.host.1, "httpbin.org");
                assert_eq!(item.port, 443);
                assert_eq!(item.protocol, Scheme::HTTPS);
                assert_eq!(item.method, Method::POST);
                assert_eq!(item.path, "/post");
                assert_eq!(item.extension, None);
                assert_eq!(item.request.0.base64, true);
                assert_eq!(item.request.1.starts_with(b"UE9TVC"), true);
                assert_eq!(item.request.1.ends_with(b"0Ke30="), true);
                assert_eq!(item.status, 200);
                assert_eq!(item.response_length, 614);
                assert_eq!(item.mimetype, "JSON");
                assert_eq!(item.response.0.base64, true);
                assert_eq!(item.response.1.starts_with(b"SFRUUC"), true);
                assert_eq!(item.response.1.ends_with(b"IKfQo="), true);
                assert_eq!(item.comment, None);
            }
            Some(Err(err)) => {
                eprintln!("{}", err);
                assert!(false, err);
            }
            None => assert!(false),
        }

        assert!(items.next().is_none());

        Ok(())
    }

    #[test]
    fn test_v_2020_12_1() -> Result<(), String> {
        let file =
            File::open("tests/http_history_files/burpsuite_community_v2020.12.1.xml").unwrap();
        let buf_reader = BufReader::new(file);
        let mut items = Items::from_reader(buf_reader).map_err(|err| err.to_string())?;

        assert_eq!(items.attr.burp_version, "2020.12.1");
        assert_eq!(
            items.attr.export_time,
            NaiveDate::from_ymd(2021, 1, 6).and_hms(11, 36, 18)
        );

        match items.next() {
            Some(Ok(item)) => {
                assert_eq!(
                    item.time,
                    NaiveDate::from_ymd(2021, 1, 6).and_hms(11, 36, 3)
                );
                assert_eq!(item.url, "http://httpbin.org/get?foo=bar");
                assert_eq!(item.host.0.ip, b"184.72.216.47");
                assert_eq!(item.host.1, "httpbin.org");
                assert_eq!(item.port, 80);
                assert_eq!(item.protocol, Scheme::HTTP);
                assert_eq!(item.method, Method::GET);
                assert_eq!(item.path, "/get?foo=bar");
                assert_eq!(item.extension, None);
                assert_eq!(item.request.0.base64, true);
                assert_eq!(item.request.1.starts_with(b"R0VUIC"), true);
                assert_eq!(item.request.1.ends_with(b"UNCg0K"), true);
                assert_eq!(item.status, 200);
                assert_eq!(item.response_length, 508);
                assert_eq!(item.mimetype, "JSON");
                assert_eq!(item.response.0.base64, true);
                assert_eq!(item.response.1.starts_with(b"SFRUUC"), true);
                assert_eq!(item.response.1.ends_with(b"p9Cg=="), true);
                assert_eq!(item.comment, None);
            }
            Some(Err(err)) => {
                eprintln!("{}", err);
                assert!(false, err);
            }
            None => assert!(false),
        }

        match items.next() {
            Some(Ok(item)) => {
                assert_eq!(
                    item.time,
                    NaiveDate::from_ymd(2021, 1, 6).and_hms(11, 36, 6)
                );
                assert_eq!(item.url, "https://httpbin.org/post");
                assert_eq!(item.host.0.ip, b"184.72.216.47");
                assert_eq!(item.host.1, "httpbin.org");
                assert_eq!(item.port, 443);
                assert_eq!(item.protocol, Scheme::HTTPS);
                assert_eq!(item.method, Method::POST);
                assert_eq!(item.path, "/post");
                assert_eq!(item.extension, None);
                assert_eq!(item.request.0.base64, true);
                assert_eq!(item.request.1.starts_with(b"UE9TVC"), true);
                assert_eq!(item.request.1.ends_with(b"0Ke30="), true);
                assert_eq!(item.status, 200);
                assert_eq!(item.response_length, 614);
                assert_eq!(item.mimetype, "JSON");
                assert_eq!(item.response.0.base64, true);
                assert_eq!(item.response.1.starts_with(b"SFRUUC"), true);
                assert_eq!(item.response.1.ends_with(b"IKfQo="), true);
                assert_eq!(item.comment, None);
            }
            Some(Err(err)) => {
                eprintln!("{}", err);
                assert!(false, err);
            }
            None => assert!(false),
        }

        assert!(items.next().is_none());

        Ok(())
    }
}
