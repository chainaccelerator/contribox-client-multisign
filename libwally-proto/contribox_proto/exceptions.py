class ContriboxError(Exception):
    """Base class for all tool errors"""
    pass


class InvalidAddressError(ContriboxError):
    """Found an invalid address"""


class UnexpectedValueError(ContriboxError):
    """Found an unexpected value"""


class MissingValueError(ContriboxError):
    """An value the tool expects is missing"""


class FeeRateError(ContriboxError):
    """Invalid fee rate value"""


class UnblindError(ContriboxError):
    """Unable to fully unblind the transaction"""


class UnsignedTransactionError(ContriboxError):
    """Transaction is not fully signed"""


class InvalidTransactionError(ContriboxError):
    """Transaction won't be accepted by mempool"""


class UnsupportedLiquidVersionError(ContriboxError):
    """Liquid version running is below minimum supported"""


class UnsupportedWalletVersionError(ContriboxError):
    """Wallet version is below minimum supported"""


class LockedWalletError(ContriboxError):
    """Wallet is locked"""


class InvalidAssetIdError(ContriboxError):
    """Asset id or already in the wallet"""


class InvalidAssetLabelError(ContriboxError):
    """Asset label already set"""
