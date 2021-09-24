import gzip
import os
import re

from insights.core.context import FSRoots
from insights.core.spec_factory import TextFileProvider, RawFileProvider, simple_file
from insights.core.plugins import datasource


class recursive_dir(object):
    """
    Creates a datasource that recursively reads all the files in a directory

    Args:
        path (str): path of the directory to traverse
        context (ExecutionContext): the context under which the datasource
            should run.
        kind (FileProvider): One of TextFileProvider or RawFileProvider
        include (str): regular expression defining paths to include.
        ignore (str): regular expression defining paths to ignore.

    Returns:
        function: A datasource that reads all files matching the glob patterns.
    """

    def __init__(
        self,
        path,
        context=None,
        include=None,
        ignore=None,
        kind=TextFileProvider,
        deps=[],
    ):
        self.path = path
        self.context = context or FSRoots
        self.kind = kind
        self.ignore_func = re.compile(ignore).search if ignore else lambda x: False
        self.include_func = re.compile(include).search if include else lambda x: True
        self.__name__ = self.__class__.__name__
        datasource(self.context, *deps, multi_output=True, raw=kind is RawFileProvider)(
            self
        )

    def __call__(self, broker):
        ctx = broker.get(self.context)
        root = ctx.root
        path = ctx.locate_path(os.path.join(root, self.path.lstrip("/")))
        results = self._listdir(ctx, root, path)
        return results

    def _listdir(self, ctx, root, path):
        result = []
        for entry in os.listdir(path):
            entry_path = os.path.join(path, entry)
            if os.path.isdir(entry_path):
                result.extend(self._listdir(ctx, root, entry_path))
            else:
                if not self.include_func(entry_path) or self.ignore_func(entry_path):
                    continue
                result.append(
                    self.kind(entry_path[len(root) :], root=root, ds=self, ctx=ctx)
                )
        return result


class GZFileProvider(RawFileProvider):
    """
    Class used in datasources that returns the contents of a gzipped file as
    a list of lines
    """

    def load(self):
        self.loaded = True
        with gzip.open(self.path, "rt", encoding="utf-8") as f:
            return [l.rstrip("\n") for l in f]
