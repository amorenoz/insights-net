import re
import os

from insights.core.context import MustGatherContext, ExecutionContext, FSRoots
from insights.core.plugins import datasource, parser
from insights.parsers import SkipException

from insights.core.spec_factory import TextFileProvider, RawFileProvider, simple_file

from insights import YAMLParser

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
    def __init__(self, path, context=None, include=None , ignore=None, kind=TextFileProvider, deps=[]):
        self.path = path
        self.context = context or FSRoots
        self.kind = kind
        self.ignore_func = re.compile(ignore).search if ignore else lambda x: False
        self.include_func = re.compile(include).search if include else lambda x: True
        self.__name__ = self.__class__.__name__
        datasource(self.context, *deps, multi_output=True, raw=kind is RawFileProvider)(self)

    def __call__(self, broker):
        ctx = broker.get(self.context)
        root = ctx.root
        path = ctx.locate_path(os.path.join(root, self.path.lstrip('/')))
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
                result.append(self.kind(entry_path[len(root):], root=root, ds=self, ctx=ctx))
        return result


netconf = simple_file("cluster-scoped-resources/config.openshift.io/networks.yaml",
                      contexte = MustGatherContext)

@parser(netconf, context = MustGatherContext)
class OCPNetConf(YAMLParser):
    """
    Contains the OCP network configuration yaml
    """
    pass

class OCPNamespaceResource(YAMLParser):
    """
    Base class parser for the files in: "namespaces/$NAMESPACE/$RESOURCE_TYPE
    """
    def __init__(self, *args, **kwargs):
        super(OCPNamespaceResource, self).__init__(*args, **kwargs)

    def parse_content(self, content):
        subpath = self.file_path.rpartition('namespaces/')
        if not subpath[2]:
            raise SkipException("Invalid Path: not a valid OCPNamespace resource")

        subpath = subpath[2]
        self.namespace = subpath.split('/')[0]
        self.resource_type = subpath.split('/')[1]
        self.resource = subpath.split('/')[2].split('.')[0]

        return super(OCPNamespaceResource, self).parse_content(content)

"""
Files in {namespace}/core/
"""
services = recursive_dir("namespaces", include="core/services.yaml", context = MustGatherContext)
@parser(services, context = MustGatherContext)
class OCPServices(OCPNamespaceResource):
    pass

pods = recursive_dir("namespaces", include="core/pods.yaml", context = MustGatherContext)
@parser(pods, context = MustGatherContext)
class OCPPods(OCPNamespaceResource):
    pass

configmaps = recursive_dir("namespaces", include="core/configmaps.yaml", context = MustGatherContext)
@parser(configmaps, context = MustGatherContext)
class OCPConfigMaps(OCPNamespaceResource):
    pass

events = recursive_dir("namespaces", include="core/events.yaml", context = MustGatherContext)
@parser(events, context = MustGatherContext)
class OCPEvents(OCPNamespaceResource):
    pass

endpoints = recursive_dir("namespaces", include="core/endpoints.yaml", context = MustGatherContext)
@parser(endpoints, context = MustGatherContext)
class OCPEndpoints(OCPNamespaceResource):
    pass

persistentvolumeclaims = recursive_dir("namespaces", include="core/persistentvolumeclaims.yaml", context = MustGatherContext)
@parser(persistentvolumeclaims, context = MustGatherContext)
class OCPPersistentVolumeClaims(OCPNamespaceResource):
    pass

replicationcontrollers = recursive_dir("namespaces", include="core/replicationcontrollers.yaml", context = MustGatherContext)
@parser(replicationcontrollers, context = MustGatherContext)
class OCPReplicationControllers(OCPNamespaceResource):
    pass

secrets = recursive_dir("namespaces", include="core/secrets.yaml", context = MustGatherContext)
@parser(secrets, context = MustGatherContext)
class OCPSecrets(OCPNamespaceResource):
    pass

"""
Files in {namespace}/apps/
"""
daemonsets = recursive_dir("namespaces", include="apps/daemonsets.yaml", context = MustGatherContext)
@parser(daemonsets, context = MustGatherContext)
class OCPDaemonsets(OCPNamespaceResource):
    pass

deployments = recursive_dir("namespaces", include="apps/deployments.yaml", context = MustGatherContext)
@parser(deployments, context = MustGatherContext)
class OCPDeployments(OCPNamespaceResource):
    pass

replicasets = recursive_dir("namespaces", include="apps/replicasets.yaml", context = MustGatherContext)
@parser(replicasets, context = MustGatherContext)
class OCPReplicaSets(OCPNamespaceResource):
    pass

statefulsets = recursive_dir("namespaces", include="apps/statefulsets.yaml", context = MustGatherContext)
@parser(statefulsets, context = MustGatherContext)
class OCPStatefulSets(OCPNamespaceResource):
    pass

routes = recursive_dir("namespaces", include="route.openshift.io/routes.yaml", context = MustGatherContext)
@parser(routes, context = MustGatherContext)
class OCPRoutes(OCPNamespaceResource):
    pass

