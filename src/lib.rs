use std::{collections::VecDeque, fmt};

const ASCII_ALPHABET: &'static str = r#" 1234567890!@#$%^&*()`~-_=+abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ[]{}\|;:'",.<>/?"#;

type Result<T> = std::result::Result<T, OneTimePadError>;

/// Possible errors whilst working with one time pads.
#[derive(Debug)]
pub enum OneTimePadError {
    /// The pad buffer isn't long enough for the input string to be processed.
    /// Append some more characters to the pad buffer with `push_to_pad` or
    /// use a shorter input string.
    PadBufferNotLongEnough,

    /// One of the characters provided is not in the alphabet and therefore
    /// cannot be processed. If you need to use this character, initialise a
    /// new [`OneTimePad`] with the `new_with_alphabet` function.
    CharacterNotInAlphabet(char),
}

impl fmt::Display for OneTimePadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PadBufferNotLongEnough => write!(
                f,
                "The pad buffer isn't long enough for the input string to be processed."
            ),
            Self::CharacterNotInAlphabet(ch) => write!(
                f,
                "The character '{ch}' is not in the alphabet of this one time pad."
            ),
        }
    }
}

/// The result of an encoding operation from [`OneTimePad`].
#[derive(Clone, Debug)]
pub struct EncodingResult {
    /// The cipher text produced from the encoding operation.
    pub cipher_text: String,
    /// The pad data used in the encoding operation.
    pub pad: String,
}

/// A struct containing the state of a one time pad. It contains a buffer of
/// pad characters which is used to encode and decode strings.
///
/// ## Encoding
/// To encode a string with the default alphabet:
/// ```
/// use onetimepad::OneTimePad;
///
/// let mut otp = OneTimePad::new();
/// otp.push_to_pad("8t5l!Ok2v$q4e3/S3dOLztDY").unwrap();
/// let res = otp.encode("Never gonna give you up.").unwrap();
/// println!("{}", res.cipher_text);
/// ```
///
/// ## Decoding
/// To decode a string with the default alphabet:
/// ```
/// use onetimepad::OneTimePad;
///
/// let mut otp = OneTimePad::new();
/// otp.push_to_pad("kgx:?exP2B8").unwrap();
/// let res = otp.decode("g2Vt1~.UjTq").unwrap();
/// println!("{}", res);
/// ```
#[derive(Clone)]
pub struct OneTimePad {
    alphabet: String,
    pad_buffer: VecDeque<usize>,
}

impl OneTimePad {
    /// Create a new [`OneTimePad`] instance with the default alphabet, which
    /// covers ASCII, except control characters.
    pub fn new() -> Self {
        Self::new_with_alphabet(String::from(ASCII_ALPHABET))
    }

    /// Create a new [`OneTimePad`] instance with a custom alphabet. The first
    /// character in the string will be numbered 0, and the numeric
    /// representation will increase with the character index.
    pub fn new_with_alphabet<S: AsRef<str>>(alphabet: S) -> Self {
        Self {
            alphabet: String::from(alphabet.as_ref()),
            pad_buffer: VecDeque::new(),
        }
    }

    fn char_to_scalar(&self, ch: char) -> Result<usize> {
        self.alphabet
            .find(ch)
            .ok_or(OneTimePadError::CharacterNotInAlphabet(ch))
    }

    fn scalar_to_char(&self, sc: usize) -> char {
        let sc = sc % self.alphabet.len();
        self.alphabet.chars().nth(sc).unwrap()
    }

    /// Push a string of characters to the end of the pad buffer. This will
    /// return a [`OneTimePadError::CharacterNotInAlphabet`] error if any of
    /// the characters are not in the alphabet for this one time pad.
    pub fn push_to_pad<S: AsRef<str>>(&mut self, extra_pad_characters: S) -> Result<()> {
        for ch in extra_pad_characters.as_ref().chars() {
            self.pad_buffer.push_back(self.char_to_scalar(ch)?);
        }
        Ok(())
    }

    #[cfg(feature = "rand")]
    /// Generate a random pad capable of encoding or decoding a string of the
    /// given size. The random generator is not guaranteed to be secure.
    pub fn generate_pad(&mut self, size: usize) {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        for _ in 0..size {
            let rand_val = rng.gen_range(0..self.alphabet.len());
            self.pad_buffer.push_back(rand_val);
        }
    }

    /// Empty the pad buffer completely.
    pub fn clear_pad(&mut self) {
        self.pad_buffer.clear();
    }

    /// Encode a string to ciphertext.
    ///
    /// The following requirements must be met for this to succeed:
    /// - The pad must contain at least the same number of characters as the
    /// input string, otherwise a [`OneTimePadError::PadBufferNotLongEnough`]
    /// will be returned.
    /// - The input text must not contain any characters not in the alphabet,
    /// otherwise a [`OneTimePadError::CharacterNotInAlphabet`] will be
    /// returned.
    ///
    /// In the event that an error is returned, the pad will not have been
    /// changed.
    pub fn encode<S: AsRef<str>>(&mut self, plain_text: S) -> Result<EncodingResult> {
        if self.pad_buffer.len() < plain_text.as_ref().len() {
            return Err(OneTimePadError::PadBufferNotLongEnough);
        }
        // Check before modifying pad
        for ch in plain_text.as_ref().chars() {
            self.char_to_scalar(ch)?;
        }

        let mut cipher_text = String::new();
        let mut pad = String::new();
        for ch in plain_text.as_ref().chars() {
            let v = self.char_to_scalar(ch)? as isize;
            let p = self.pad_buffer.pop_front().unwrap() as isize;
            let mut c: isize = v - p;
            if c < 0 {
                c += self.alphabet.len() as isize;
            }
            cipher_text.push(self.scalar_to_char(c as usize));
            pad.push(self.scalar_to_char(p as usize));
        }
        Ok(EncodingResult { cipher_text, pad })
    }

    /// Encode ciphertext to plain text.
    ///
    /// The following requirements must be met for this to succeed:
    /// - The pad must contain at least the same number of characters as the
    /// input string, otherwise a [`OneTimePadError::PadBufferNotLongEnough`]
    /// will be returned.
    /// - The input text must not contain any characters not in the alphabet,
    /// otherwise a [`OneTimePadError::CharacterNotInAlphabet`] will be
    /// returned.
    ///
    /// In the event that an error is returned, the pad will not have been
    /// changed.
    pub fn decode<S: AsRef<str>>(&mut self, cipher_text: S) -> Result<String> {
        if self.pad_buffer.len() < cipher_text.as_ref().len() {
            return Err(OneTimePadError::PadBufferNotLongEnough);
        }
        // Check before modifying pad
        for ch in cipher_text.as_ref().chars() {
            self.char_to_scalar(ch)?;
        }

        let mut plaintext = String::new();
        for ch in cipher_text.as_ref().chars() {
            let v = self.char_to_scalar(ch)?;
            let p = self.pad_buffer.pop_front().unwrap();
            let c = (v + p) % self.alphabet.len();
            plaintext.push(self.scalar_to_char(c));
        }
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use crate::OneTimePad;

    #[test]
    fn test_correctly_encode() -> super::Result<()> {
        let mut otp = OneTimePad::new();
        otp.push_to_pad("kgx:?exP2B8")?;
        let res = otp.encode("Rick Astley")?;
        assert_eq!(res.cipher_text, "g2Vt1~.UjTq");
        Ok(())
    }

    #[test]
    fn test_correctly_decode() -> super::Result<()> {
        let mut otp = OneTimePad::new();
        otp.push_to_pad("kgx:?exP2B8")?;
        let res = otp.decode("g2Vt1~.UjTq")?;
        assert_eq!(res, "Rick Astley");
        Ok(())
    }

    #[test]
    fn test_custom_alphabet() -> super::Result<()> {
        // ABCDE
        // 01234

        // X: BCD -> 123
        // Y: BED -> 143
        // X-Y:      020
        //           ACA

        let mut otp = OneTimePad::new_with_alphabet("ABCDE");
        otp.push_to_pad("BCD")?;
        let res = otp.encode("BED")?;
        assert_eq!(res.cipher_text, "ACA");
        Ok(())
    }

    #[test]
    fn test_pad_too_short() -> super::Result<()> {
        let mut otp = OneTimePad::new();
        otp.push_to_pad("kgx")?;
        let res = otp.decode("g2Vt1~.UjTq");
        let err = res.expect_err("pad shouldn't have been long enough");
        match err {
            crate::OneTimePadError::PadBufferNotLongEnough => (),
            _ => panic!("this shouldn't be the returned error!"),
        }
        Ok(())
    }

    #[test]
    fn test_char_not_in_alphabet() -> super::Result<()> {
        let mut otp = OneTimePad::new_with_alphabet("ABCDE");
        let res = otp.push_to_pad("WHOOPS");
        let err = res.expect_err("characters shouldn't have been valid in pad");
        match err {
            crate::OneTimePadError::CharacterNotInAlphabet(c) => assert_eq!(c, 'W'),
            _ => panic!("this shouldn't be the returned error!"),
        }
        Ok(())
    }
}
