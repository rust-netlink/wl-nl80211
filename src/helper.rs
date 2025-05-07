pub(crate) mod emit {
    pub(crate) struct FieldFlags<'a> {
        flags: &'a [bool],
        pos: usize,
    }

    impl<'a> FieldFlags<'a> {
        pub(crate) fn new(flags: &'a [bool]) -> Self {
            Self { flags, pos: 0 }
        }

        pub(crate) fn should_emit(&mut self) -> bool {
            let emit = self.flags[self.pos..].iter().any(|&f| f);
            self.pos += 1;
            emit
        }
    }
}
