use anyhow::Result;
use std::collections::HashMap;

#[derive(Default)]
struct User<'a> {
    name: String,
    sign_key: &'a [u8],
    verify_key: &'a [u8],
    symmetric_key: &'a [u8],
    db_filepath: String,
}

impl User<'_> {
    pub fn new(
        name: String,
        sign_key: &[u8],
        verify_key: &[u8],
        symmetric_key: &[u8],
        db_filepath: String,
    ) -> Self {
        User::default()
        // User {
        //     name,
        //     sign_key,
        //     verify_key,
        //     symmetric_key,
        //     db_filepath,
        // }
    }
}

pub fn create() -> Result<()> {
    Ok(())
}

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
