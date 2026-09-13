import sys
import types
from dataclasses import dataclass
from typing import Any, Dict, List

class UserError(Exception):
    pass

class Address(str):
    def __new__(cls, val):
        return super().__new__(cls, str(val))

class u256(int):
    pass

class bigint(int):
    pass

class TreeMap(dict):
    pass

class DynArray(list):
    pass

def allow_storage(cls):
    return cls

class MockMessage:
    def __init__(self, sender="0x1111111111111111111111111111111111111111", value=0):
        self.sender_address = Address(sender)
        self.value = bigint(value)

class MockGL:
    def __init__(self):
        self.message = MockMessage()
        self.message_raw = {"datetime": "2026-09-13T12:00:00Z"}
        self.evm = types.SimpleNamespace(
            contract_interface=lambda cls: cls
        )
        self.public = types.SimpleNamespace(
            write=lambda fn: fn,
            view=lambda fn: fn,
        )
        self.public.write.payable = lambda fn: fn
        self.Contract = object
        self.nondet = types.SimpleNamespace()
        self.vm = types.SimpleNamespace()

# Create synthetic module 'genlayer'
mock_genlayer = types.ModuleType("genlayer")
gl_instance = MockGL()
mock_genlayer.gl = gl_instance
mock_genlayer.Address = Address
mock_genlayer.u256 = u256
mock_genlayer.bigint = bigint
mock_genlayer.TreeMap = TreeMap
mock_genlayer.DynArray = DynArray
mock_genlayer.allow_storage = allow_storage
mock_genlayer.UserError = UserError

sys.modules["genlayer"] = mock_genlayer
