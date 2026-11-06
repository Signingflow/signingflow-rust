use std::collections::HashSet;
use std::sync::Arc;

use crate::error::Error;

const MAX_PAGES: u32 = 100;

type Loader<T> = Arc<dyn Fn(&str) -> Result<Page<T>, Error> + Send + Sync>;

/// One page of results. Iteration keeps the original loader.
pub struct Page<T> {
    pub data: Vec<T>,
    pub next_page_token: String,
    pub(crate) load: Option<Loader<T>>,
}

impl<T> Page<T> {
    pub(crate) fn new(data: Vec<T>, next_page_token: String) -> Self {
        Self { data, next_page_token, load: None }
    }
}

impl<T> IntoIterator for Page<T> {
    type Item = Result<T, Error>;
    type IntoIter = PageIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        PageIter {
            data: self.data,
            token: self.next_page_token,
            load: self.load,
            seen: HashSet::new(),
            pages: 0,
            finished: false,
        }
    }
}

pub struct PageIter<T> {
    data: Vec<T>,
    token: String,
    load: Option<Loader<T>>,
    seen: HashSet<String>,
    pages: u32,
    finished: bool,
}

impl<T> Iterator for PageIter<T> {
    type Item = Result<T, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.finished {
                return None;
            }
            if !self.data.is_empty() {
                return Some(Ok(self.data.remove(0)));
            }
            if self.token.is_empty() || self.load.is_none() || self.seen.contains(&self.token) {
                self.finished = true;
                return None;
            }
            self.pages += 1;
            if self.pages > MAX_PAGES {
                self.finished = true;
                return Some(Err(Error::invalid("Too many pages.")));
            }
            let token = self.token.clone();
            self.seen.insert(token.clone());
            let loaded = (self.load.as_ref().expect("loader"))(&token);
            match loaded {
                Ok(page) => {
                    self.data = page.data;
                    self.token = page.next_page_token;
                }
                Err(err) => {
                    self.finished = true;
                    return Some(Err(err));
                }
            }
        }
    }
}

pub(crate) fn page_size(value: Option<u32>) -> Result<u32, Error> {
    match value {
        None => Ok(10),
        Some(size) if (1..=1000).contains(&size) => Ok(size),
        Some(_) => Err(Error::invalid("pageSize must be a whole number from 1 to 1000.")),
    }
}
