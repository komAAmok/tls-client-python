"""Pin the interpreter floor that requires-python advertises: 3.6 to 3.14.

The suite always runs on one interpreter, so nothing else catches a construct
that parses here and dies on 3.6 - and one already shipped: an unguarded
``from typing import Protocol`` is fine on 3.8+ and an ImportError on 3.6/3.7,
which killed `import tls_client` outright because tls_client/__init__.py
imports every submodule eagerly.

Three failure modes are covered, all AST-only (no network, no native library,
no second interpreter):

1. **Syntax** - walrus, ``def f(a, /)``, ``match``, PEP 695 ``type`` aliases and
   friends do not compile at all on 3.6.
2. **typing names** - PEP 544/585/586/604/612/646/655/675/696/695 each added
   names to ``typing``; importing one unguarded is an ImportError at import time.
   The project pattern for a newer name is a ``try`` whose handler catches
   ``ImportError`` and falls back to typing_extensions (see tls_client/_core.py).
3. **Runtime-evaluated annotations** - ``list[int]`` and ``int | None`` are legal
   syntax on 3.6 but raise TypeError when the annotation is evaluated, and no
   module here uses ``from __future__ import annotations``.

Keep PACKAGE_SYNTAX_FLOOR in step with requires-python: if the floor is ever
raised, this file changes with it, deliberately.
"""

import ast
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_DIR = REPO_ROOT / "tls_client"

#: The oldest interpreter the package claims to support.
PACKAGE_SYNTAX_FLOOR = (3, 6)

#: Everything CPython 3.6's typing module exported. A name outside this set must
#: be imported behind a try/except ImportError, or it is a 3.6 ImportError.
PY36_TYPING = frozenset(
    """
    TYPE_CHECKING AbstractSet Any AnyStr AsyncContextManager AsyncGenerator
    AsyncIterable AsyncIterator Awaitable Callable ChainMap ClassVar Collection
    Container ContextManager Coroutine Counter DefaultDict Deque Dict FrozenSet
    Generator Generic Hashable IO ItemsView Iterable Iterator KeysView List
    Mapping MutableMapping MutableSequence MutableSet NamedTuple NewType NoReturn
    Optional Pattern Match Reversible Sequence Set Sized SupportsAbs
    SupportsBytes SupportsComplex SupportsFloat SupportsInt Text Tuple Type
    TypeVar Union ValuesView cast get_type_hints no_type_check
    no_type_check_decorator overload
    """.split()
)

#: typing names added after 3.6, and the version that added them.
TOO_NEW_TYPING = {
    "Protocol": "3.8",
    "runtime_checkable": "3.8",
    "Final": "3.8",
    "final": "3.8",
    "Literal": "3.8",
    "TypedDict": "3.8",
    "get_origin": "3.8",
    "get_args": "3.8",
    "Annotated": "3.9",
    "TypeAlias": "3.10",
    "ParamSpec": "3.10",
    "Concatenate": "3.10",
    "TypeGuard": "3.10",
    "is_typeddict": "3.10",
    "Self": "3.11",
    "LiteralString": "3.11",
    "Never": "3.11",
    "Required": "3.11",
    "NotRequired": "3.11",
    "TypeVarTuple": "3.11",
    "Unpack": "3.11",
    "assert_type": "3.11",
    "assert_never": "3.11",
    "dataclass_transform": "3.11",
    "TypeAliasType": "3.12",
    "override": "3.12",
    "Buffer": "3.12",
    "TypeIs": "3.13",
    "NoDefault": "3.13",
    "ReadOnly": "3.13",
    "TypeForm": "3.14",
}

#: PEP 585 generic aliases: ``list[int]`` is a TypeError on 3.6/3.7/3.8.
BUILTIN_GENERICS = frozenset({"list", "dict", "tuple", "set", "frozenset", "type"})


def package_modules():
    """Every module that ships inside the wheel, sorted for stable output."""
    return sorted(PACKAGE_DIR.rglob("*.py"))


def parse_module(path, feature_version=None):
    source = path.read_text(encoding="utf-8")
    return ast.parse(source, filename=str(path), feature_version=feature_version)


def catches_import_error(handler):
    if handler.type is None:  # bare except
        return True
    caught = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
    return any(
        isinstance(node, ast.Name)
        and node.id in ("ImportError", "ModuleNotFoundError", "Exception", "BaseException")
        for node in caught
    )


def typing_references(node, guarded=False):
    """Yield (name, lineno, guarded) for every ``typing`` name used in *node*.

    Both spellings are reported: ``from typing import X`` (an ImportFrom) and
    ``typing.X`` (an Attribute).  ``guarded`` is True when the use sits in a
    ``try`` body whose handler catches ImportError - the project pattern for a
    name that only exists on newer interpreters.
    """
    for child in ast.iter_child_nodes(node):
        if isinstance(child, ast.Try):
            inner = guarded or any(catches_import_error(h) for h in child.handlers)
            branches = (
                [child.body]
                + [list(h.body) for h in child.handlers]
                + [child.orelse, child.finalbody]
            )
            for index, branch in enumerate(branches):
                for statement in branch:
                    for item in typing_references(statement, inner if index == 0 else guarded):
                        yield item
            continue
        if isinstance(child, ast.ImportFrom) and child.module == "typing" and not child.level:
            for alias in child.names:
                yield alias.name, child.lineno, guarded
        elif isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name):
            if child.value.id == "typing":
                yield child.attr, child.lineno, guarded
        for item in typing_references(child, guarded):
            yield item


def has_future_annotations(tree):
    return any(
        isinstance(node, ast.ImportFrom)
        and node.module == "__future__"
        and any(alias.name == "annotations" for alias in node.names)
        for node in ast.walk(tree)
    )


def annotations_of(tree):
    """Yield every annotation expression that is evaluated at definition time."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = node.args
            for argument in (
                list(args.posonlyargs)
                + list(args.args)
                + list(args.kwonlyargs)
                + [args.vararg, args.kwarg]
            ):
                if argument is not None and argument.annotation is not None:
                    yield argument.annotation
            if node.returns is not None:
                yield node.returns
        elif isinstance(node, ast.AnnAssign):
            yield node.annotation


def runtime_hazards(annotation):
    """Yield a description for each PEP 585 / PEP 604 construct in *annotation*."""
    for node in ast.walk(annotation):
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
            if node.value.id in BUILTIN_GENERICS:
                yield "line %d: %s[...] is PEP 585 (3.9+)" % (
                    node.lineno,
                    node.value.id,
                )
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            yield "line %d: 'X | Y' is PEP 604 (3.10+)" % node.lineno


class PackageSyntaxFloorTest(unittest.TestCase):
    """Guard the 3.6 syntax floor for the shipped package."""

    def test_every_module_parses_as_python36(self):
        problems = []
        for path in package_modules():
            try:
                parse_module(path, feature_version=PACKAGE_SYNTAX_FLOOR)
            except SyntaxError as exc:
                problems.append(
                    "%s:%s: %s (needs a newer interpreter than %d.%d)"
                    % (path, exc.lineno, exc.msg, *PACKAGE_SYNTAX_FLOOR)
                )
        self.assertEqual([], problems, "\n".join(["", "not Python 3.6 syntax:", *problems]))

    def test_no_unguarded_post_python36_typing_reference(self):
        problems = []
        for path in package_modules():
            tree = parse_module(path)
            for name, lineno, guarded in typing_references(tree):
                if name in PY36_TYPING:
                    continue
                introduced = TOO_NEW_TYPING.get(name)
                if introduced is None:
                    problems.append(
                        "%s:%d: typing.%s is not in the 3.6 stdlib; add it to "
                        "PY36_TYPING or TOO_NEW_TYPING" % (path, lineno, name)
                    )
                elif not guarded:
                    problems.append(
                        "%s:%d: typing.%s needs Python %s - import it behind "
                        "try/except ImportError" % (path, lineno, name, introduced)
                    )
        self.assertEqual([], problems, "\n".join(["", "3.6 typing floor broken:", *problems]))

    def test_no_runtime_evaluated_pep585_or_pep604_annotations(self):
        problems = []
        for path in package_modules():
            tree = parse_module(path)
            if has_future_annotations(tree):
                continue
            for annotation in annotations_of(tree):
                for hazard in runtime_hazards(annotation):
                    problems.append("%s: %s" % (path, hazard))
        self.assertEqual([], problems, "\n".join(["", "annotation evaluated on 3.6:", *problems]))

    def test_the_floor_and_its_fallback_dependency_are_declared(self):
        pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        setup_py = (REPO_ROOT / "setup.py").read_text(encoding="utf-8")
        self.assertIn('requires-python = ">=3.6, <3.15"', pyproject)
        self.assertIn('python_requires=">=3.6,<3.15"', setup_py)
        # typing_extensions is what the try/except fallbacks import, so it must
        # be installed wherever typing lacks the newer names.
        for name, text in (("pyproject.toml", pyproject), ("setup.py", setup_py)):
            self.assertRegex(
                text,
                r"typing_extensions[^\n]*python_version\s*<\s*'3\.7'",
                "%s must keep installing typing_extensions on 3.6" % name,
            )


if __name__ == "__main__":
    unittest.main()
