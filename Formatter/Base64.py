from Formatter import AbstractFormatter
import base64


class Base64(AbstractFormatter):
    BASE64_VARIANT_ORIGINAL = 1
    BASE64_VARIANT_ORIGINAL_NO_PADDING = 3
    BASE64_VARIANT_URLSAFE = 5
    BASE64_VARIANT_URLSAFE_NO_PADDING = 7
    ALTCHARS = b'-_'

    variant = None
    strict = False

    def __init__(self, variant, strict=False):
        assert (variant == self.BASE64_VARIANT_ORIGINAL) or (variant == self.BASE64_VARIANT_ORIGINAL_NO_PADDING) or (
                variant == self.BASE64_VARIANT_URLSAFE) or (variant == self.BASE64_VARIANT_URLSAFE_NO_PADDING)
        assert isinstance(strict, bool)
        self.variant = variant

    def format(self, value):
        if (self.variant == self.BASE64_VARIANT_ORIGINAL) or (self.variant == self.BASE64_VARIANT_ORIGINAL_NO_PADDING):
            fmt_value = base64.b64encode(value, None)
        elif (self.variant == self.BASE64_VARIANT_URLSAFE) or (self.variant == self.BASE64_VARIANT_URLSAFE_NO_PADDING):
            fmt_value = base64.b64encode(value, self.ALTCHARS)
        else:
            raise RuntimeError("Invalid encoding variant")
        if (self.variant == self.BASE64_VARIANT_ORIGINAL) or (self.variant == self.BASE64_VARIANT_URLSAFE):
            return fmt_value
        return fmt_value.rstrip(b'=')

    def parse(self, value):
        return base64.b64decode(value, self.ALTCHARS, self.strict)
