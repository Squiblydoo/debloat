import enum
class RSRC(enum.IntEnum):
    CURSOR        = 0x01  # noqa
    BITMAP        = 0x02  # noqa
    ICON          = 0x03  # noqa
    MENU          = 0x04  # noqa
    DIALOG        = 0x05  # noqa
    STRING        = 0x06  # noqa
    FONTDIR       = 0x07  # noqa
    FONT          = 0x08  # noqa
    ACCELERATOR   = 0x09  # noqa
    RCDATA        = 0x0A  # noqa
    MESSAGETABLE  = 0x0B  # noqa
    ICON_GROUP    = 0x0E  # noqa
    VERSION       = 0x10  # noqa
    DLGINCLUDE    = 0x11  # noqa
    PLUGPLAY      = 0x13  # noqa
    VXD           = 0x14  # noqa
    ANICURSOR     = 0x15  # noqa
    ANIICON       = 0x16  # noqa
    HTML          = 0x17  # noqa
    MANIFEST      = 0x18  # noqa

    def __str__(self):
        return self.name