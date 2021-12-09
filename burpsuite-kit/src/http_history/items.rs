use std::{
    collections::HashSet,
    convert::TryFrom,
    io::BufRead,
    iter::Iterator,
    num::ParseIntError,
    str::{self, ParseBoolError},
};

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

#[derive(thiserror::Error, Debug)]
pub enum ItemsParseError {
    #[error("XmlError {0:?}")]
    XmlError(Error),
    #[error("UnknownTag {0:?}")]
    UnknownTag(Vec<u8>),
    #[error("UnexpectedEof")]
    UnexpectedEof,
    #[error("AttrMissing {0}")]
    AttrMissing(String),
    #[error("AttrInvalid {0} {1}")]
    AttrInvalid(String, String),
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

#[derive(thiserror::Error, Debug)]
pub enum ItemParseError {
    #[error("XmlError {0:?}")]
    XmlError(Error),
    #[error("UnknownTag {0:?}")]
    UnknownTag(Vec<u8>),
    #[error("Unexpected")]
    UnexpectedEof,
    #[error("StateMismatch {0}")]
    StateMismatch(String),
    #[error("SomeTagsMissing {0:?}")]
    SomeTagsMissing(HashSet<ItemTag>),
    #[error("DuplicateTag {0:?}")]
    DuplicateTag(ItemTag),
    #[error("TagAttrMissing {0:?} {1}")]
    TagAttrMissing(ItemTag, String),
    #[error("TagAttrInvalid {0:?} {1} {2}")]
    TagAttrInvalid(ItemTag, String, String),
    #[error("TagValueMissing {0:?}")]
    TagValueMissing(ItemTag),
    #[error("TagValueInvalid {0:?} {1}")]
    TagValueInvalid(ItemTag, String),
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

                        self.item = Default::default();
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
                                State::WaitTagValue(ref wait_tag) => {
                                    if wait_tag == &tag {
                                        if self.processed_item_tags.contains(&tag) {
                                            self.state = State::WaitTag;
                                        } else {
                                            return Err(ItemParseError::TagValueMissing(
                                                wait_tag.to_owned(),
                                            ));
                                        }
                                    } else {
                                        return Err(ItemParseError::StateMismatch(format!(
                                            "expect {:?} but current {:?}",
                                            State::WaitTagValue(tag),
                                            self.state
                                        )));
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
                    State::WaitTagValue(ref tag) => {
                        let bytes = e.escaped();
                        match tag {
                            ItemTag::Time => {
                                let time = NaiveDateTime::parse_from_str(
                                    str::from_utf8(bytes).map_err(|err| {
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
                                self.item.host.1 =
                                    String::from_utf8(bytes.to_vec()).map_err(|err| {
                                        ItemParseError::TagValueInvalid(
                                            tag.to_owned(),
                                            err.to_string(),
                                        )
                                    })?;

                                self.processed_item_tags.insert(tag.to_owned());
                            }
                            ItemTag::Port => {
                                let port: u16 = str::from_utf8(bytes)
                                    .map_err(|err| {
                                        ItemParseError::TagValueInvalid(
                                            tag.to_owned(),
                                            err.to_string(),
                                        )
                                    })?
                                    .parse()
                                    .map_err(|err: ParseIntError| {
                                        ItemParseError::TagValueInvalid(
                                            tag.to_owned(),
                                            err.to_string(),
                                        )
                                    })?;

                                self.item.port = port;

                                self.processed_item_tags.insert(tag.to_owned());
                            }
                            ItemTag::Protocol => {
                                let protocol: Scheme = str::from_utf8(bytes)
                                    .map_err(|err| {
                                        ItemParseError::TagValueInvalid(
                                            tag.to_owned(),
                                            err.to_string(),
                                        )
                                    })?
                                    .parse()
                                    .map_err(|err: InvalidUri| {
                                        ItemParseError::TagValueInvalid(
                                            tag.to_owned(),
                                            err.to_string(),
                                        )
                                    })?;

                                self.item.protocol = protocol;

                                self.processed_item_tags.insert(tag.to_owned());
                            }
                            ItemTag::Extension => {
                                self.item.extension = if bytes == b"null" {
                                    None
                                } else {
                                    Some(String::from_utf8(bytes.to_vec()).map_err(|err| {
                                        ItemParseError::TagValueInvalid(
                                            tag.to_owned(),
                                            err.to_string(),
                                        )
                                    })?)
                                };

                                self.processed_item_tags.insert(tag.to_owned());
                            }
                            ItemTag::Status => {
                                let status = StatusCode::from_bytes(bytes).map_err(|err| {
                                    ItemParseError::TagValueInvalid(tag.to_owned(), err.to_string())
                                })?;

                                self.item.status = status;

                                self.processed_item_tags.insert(tag.to_owned());
                            }
                            ItemTag::ResponseLength => {
                                let response_length: u32 = str::from_utf8(bytes)
                                    .map_err(|err| {
                                        ItemParseError::TagValueInvalid(
                                            tag.to_owned(),
                                            err.to_string(),
                                        )
                                    })?
                                    .parse()
                                    .map_err(|err: ParseIntError| {
                                        ItemParseError::TagValueInvalid(
                                            tag.to_owned(),
                                            err.to_string(),
                                        )
                                    })?;

                                self.item.response_length = response_length;

                                self.processed_item_tags.insert(tag.to_owned());
                            }
                            ItemTag::Mimetype => {
                                self.item.mimetype =
                                    String::from_utf8(bytes.to_vec()).map_err(|err| {
                                        ItemParseError::TagValueInvalid(
                                            tag.to_owned(),
                                            err.to_string(),
                                        )
                                    })?;

                                self.processed_item_tags.insert(tag.to_owned());
                            }
                            ItemTag::Comment => {
                                self.item.comment = if bytes.is_empty() {
                                    None
                                } else {
                                    Some(String::from_utf8(bytes.to_vec()).map_err(|err| {
                                        ItemParseError::TagValueInvalid(
                                            tag.to_owned(),
                                            err.to_string(),
                                        )
                                    })?)
                                };

                                self.processed_item_tags.insert(tag.to_owned());
                            }
                            _ => {}
                        }
                    }
                },
                Ok(Event::CData(e)) => match self.state {
                    State::Idle => {}
                    State::WaitTag => {}
                    State::WaitTagValue(ref tag) => {
                        let bytes = e.escaped();
                        match tag {
                            ItemTag::Request => {
                                self.item.request.1 = bytes.to_vec();

                                self.processed_item_tags.insert(tag.to_owned());
                            }
                            ItemTag::Response => {
                                self.item.response.1 = bytes.to_vec();

                                self.processed_item_tags.insert(tag.to_owned());
                            }
                            ItemTag::Url => {
                                let url = String::from_utf8(bytes.to_vec()).map_err(|err| {
                                    ItemParseError::TagValueInvalid(tag.to_owned(), err.to_string())
                                })?;

                                self.item.url = url;

                                self.processed_item_tags.insert(tag.to_owned());
                            }
                            ItemTag::Method => {
                                let method = Method::from_bytes(bytes).map_err(|err| {
                                    ItemParseError::TagValueInvalid(tag.to_owned(), err.to_string())
                                })?;

                                self.item.method = method;

                                self.processed_item_tags.insert(tag.to_owned());
                            }
                            ItemTag::Path => {
                                let path = String::from_utf8(bytes.to_vec()).map_err(|err| {
                                    ItemParseError::TagValueInvalid(tag.to_owned(), err.to_string())
                                })?;

                                self.item.path = path;
                                self.processed_item_tags.insert(tag.to_owned());
                            }
                            _ => {}
                        }
                    }
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

    use std::{error, fs::File, io::BufReader};

    use chrono::NaiveDate;

    #[test]
    fn test_v_1_7_36() -> Result<(), Box<dyn error::Error>> {
        let file = File::open("tests/http_history_files/burpsuite_community_v1.7.36.xml").unwrap();
        let buf_reader = BufReader::new(file);
        let mut items = Items::from_reader(buf_reader)?;

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
                assert!(item.request.0.base64);
                assert!(item.request.1.starts_with(b"R0VUIC"));
                assert!(item.request.1.ends_with(b"UNCg0K"));
                assert_eq!(item.status, 200);
                assert_eq!(item.response_length, 508);
                assert_eq!(item.mimetype, "JSON");
                assert!(item.response.0.base64);
                assert!(item.response.1.starts_with(b"SFRUUC"));
                assert!(item.response.1.ends_with(b"p9Cg=="));
                assert_eq!(item.comment, None);
            }
            Some(Err(err)) => {
                eprintln!("{}", err);
                assert!(false, "{}", err);
            }
            None => panic!(),
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
                assert!(item.request.0.base64);
                assert!(item.request.1.starts_with(b"UE9TVC"));
                assert!(item.request.1.ends_with(b"0Ke30="));
                assert_eq!(item.status, 200);
                assert_eq!(item.response_length, 614);
                assert_eq!(item.mimetype, "JSON");
                assert!(item.response.0.base64);
                assert!(item.response.1.starts_with(b"SFRUUC"));
                assert!(item.response.1.ends_with(b"IKfQo="));
                assert_eq!(item.comment, None);
            }
            Some(Err(err)) => {
                eprintln!("{}", err);
                assert!(false, "{}", err);
            }
            None => panic!(),
        }

        assert!(items.next().is_none());

        Ok(())
    }

    #[test]
    fn test_v_2020_12_1() -> Result<(), Box<dyn error::Error>> {
        let file =
            File::open("tests/http_history_files/burpsuite_community_v2020.12.1.xml").unwrap();
        let buf_reader = BufReader::new(file);
        let mut items = Items::from_reader(buf_reader)?;

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
                assert!(item.request.0.base64);
                assert!(item.request.1.starts_with(b"R0VUIC"));
                assert!(item.request.1.ends_with(b"UNCg0K"));
                assert_eq!(item.status, 200);
                assert_eq!(item.response_length, 508);
                assert_eq!(item.mimetype, "JSON");
                assert!(item.response.0.base64);
                assert!(item.response.1.starts_with(b"SFRUUC"));
                assert!(item.response.1.ends_with(b"p9Cg=="));
                assert_eq!(item.comment, None);
            }
            Some(Err(err)) => {
                eprintln!("{}", err);
                assert!(false, "{}", err);
            }
            None => panic!(),
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
                assert!(item.request.0.base64);
                assert!(item.request.1.starts_with(b"UE9TVC"));
                assert!(item.request.1.ends_with(b"0Ke30="));
                assert_eq!(item.status, 200);
                assert_eq!(item.response_length, 614);
                assert_eq!(item.mimetype, "JSON");
                assert!(item.response.0.base64);
                assert!(item.response.1.starts_with(b"SFRUUC"));
                assert!(item.response.1.ends_with(b"IKfQo="));
                assert_eq!(item.comment, None);
            }
            Some(Err(err)) => {
                eprintln!("{}", err);
                assert!(false, "{}", err);
            }
            None => panic!(),
        }

        assert!(items.next().is_none());

        Ok(())
    }

    #[test]
    fn test_v_2021_3_2() -> Result<(), Box<dyn error::Error>> {
        let file =
            File::open("tests/http_history_files/burpsuite_community_v2021.3.2.xml").unwrap();
        let buf_reader = BufReader::new(file);
        let mut items = Items::from_reader(buf_reader)?;

        assert_eq!(items.attr.burp_version, "2021.3.2");
        assert_eq!(
            items.attr.export_time,
            NaiveDate::from_ymd(2021, 3, 31).and_hms(13, 7, 44)
        );

        match items.next() {
            Some(Ok(item)) => {
                assert_eq!(
                    item.time,
                    NaiveDate::from_ymd(2021, 3, 31).and_hms(13, 6, 6)
                );
                assert_eq!(item.url, "http://httpbin.org/get?foo=bar");
                assert_eq!(item.host.0.ip, b"34.199.75.4");
                assert_eq!(item.host.1, "httpbin.org");
                assert_eq!(item.port, 80);
                assert_eq!(item.protocol, Scheme::HTTP);
                assert_eq!(item.method, Method::GET);
                assert_eq!(item.path, "/get?foo=bar");
                assert_eq!(item.extension, None);
                assert!(item.request.0.base64);
                assert!(item.request.1.starts_with(b"R0VUIC"));
                assert!(item.request.1.ends_with(b"UNCg0K"));
                assert_eq!(item.status, 200);
                assert_eq!(item.response_length, 508);
                assert_eq!(item.mimetype, "JSON");
                assert!(item.response.0.base64);
                assert!(item.response.1.starts_with(b"SFRUUC"));
                assert!(item.response.1.ends_with(b"p9Cg=="));
                assert_eq!(item.comment, None);
            }
            Some(Err(err)) => {
                eprintln!("{}", err);
                assert!(false, "{}", err);
            }
            None => panic!(),
        }

        match items.next() {
            Some(Ok(item)) => {
                assert_eq!(
                    item.time,
                    NaiveDate::from_ymd(2021, 3, 31).and_hms(13, 6, 13)
                );
                assert_eq!(item.url, "https://httpbin.org/post");
                assert_eq!(item.host.0.ip, b"34.199.75.4");
                assert_eq!(item.host.1, "httpbin.org");
                assert_eq!(item.port, 443);
                assert_eq!(item.protocol, Scheme::HTTPS);
                assert_eq!(item.method, Method::POST);
                assert_eq!(item.path, "/post");
                assert_eq!(item.extension, None);
                assert!(item.request.0.base64);
                assert!(item.request.1.starts_with(b"UE9TVC"));
                assert!(item.request.1.ends_with(b"oNCnt9"));
                assert_eq!(item.status, 200);
                assert_eq!(item.response_length, 593);
                assert_eq!(item.mimetype, "JSON");
                assert!(item.response.0.base64);
                assert!(item.response.1.starts_with(b"SFRUUC"));
                assert!(item.response.1.ends_with(b"IKfQo="));
                assert_eq!(item.comment, None);
            }
            Some(Err(err)) => {
                eprintln!("{}", err);
                assert!(false, "{}", err);
            }
            None => panic!(),
        }

        assert!(items.next().is_none());

        Ok(())
    }
}
