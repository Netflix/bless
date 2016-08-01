# -*- coding: utf-8 -*-
from __future__ import absolute_import

import logging
import os
import warnings

from pip.basecommand import Command
from pip.index import PackageFinder
from pip.exceptions import CommandError, PreviousBuildDirError
from pip.req import InstallRequirement, RequirementSet, parse_requirements
from pip.utils import normalize_path
from pip.utils.build import BuildDirectory
from pip.utils.deprecation import RemovedInPip7Warning, RemovedInPip8Warning
from pip.wheel import WheelBuilder
from pip import cmdoptions

DEFAULT_WHEEL_DIR = os.path.join(normalize_path(os.curdir), 'wheelhouse')


logger = logging.getLogger(__name__)


class WheelCommand(Command):
    """
    Build Wheel archives for your requirements and dependencies.

    Wheel is a built-package format, and offers the advantage of not
    recompiling your software during every install. For more details, see the
    wheel docs: http://wheel.readthedocs.org/en/latest.

    Requirements: setuptools>=0.8, and wheel.

    'pip wheel' uses the bdist_wheel setuptools extension from the wheel
    package to build individual wheels.

    """

    name = 'wheel'
    usage = """
      %prog [options] <requirement specifier> ...
      %prog [options] -r <requirements file> ...
      %prog [options] [-e] <vcs project url> ...
      %prog [options] [-e] <local project path> ...
      %prog [options] <archive url/path> ..."""

    summary = 'Build wheels from your requirements.'

    def __init__(self, *args, **kw):
        super(WheelCommand, self).__init__(*args, **kw)

        cmd_opts = self.cmd_opts

        cmd_opts.add_option(
            '-w', '--wheel-dir',
            dest='wheel_dir',
            metavar='dir',
            default=DEFAULT_WHEEL_DIR,
            help=("Build wheels into <dir>, where the default is "
                  "'<cwd>/wheelhouse'."),
        )
        cmd_opts.add_option(cmdoptions.use_wheel.make())
        cmd_opts.add_option(cmdoptions.no_use_wheel.make())
        cmd_opts.add_option(
            '--build-option',
            dest='build_options',
            metavar='options',
            action='append',
            help="Extra arguments to be supplied to 'setup.py bdist_wheel'.")
        cmd_opts.add_option(cmdoptions.editable.make())
        cmd_opts.add_option(cmdoptions.requirements.make())
        cmd_opts.add_option(cmdoptions.download_cache.make())
        cmd_opts.add_option(cmdoptions.src.make())
        cmd_opts.add_option(cmdoptions.no_deps.make())
        cmd_opts.add_option(cmdoptions.build_dir.make())

        cmd_opts.add_option(
            '--global-option',
            dest='global_options',
            action='append',
            metavar='options',
            help="Extra global options to be supplied to the setup.py "
            "call before the 'bdist_wheel' command.")

        cmd_opts.add_option(
            '--pre',
            action='store_true',
            default=False,
            help=("Include pre-release and development versions. By default, "
                  "pip only finds stable versions."),
        )

        cmd_opts.add_option(cmdoptions.no_clean.make())

        index_opts = cmdoptions.make_option_group(
            cmdoptions.index_group,
            self.parser,
        )

        self.parser.insert_option_group(0, index_opts)
        self.parser.insert_option_group(0, cmd_opts)

    def run(self, options, args):

        # confirm requirements
        try:
            import wheel.bdist_wheel
            # Hack to make flake8 not complain about an unused import
            wheel.bdist_wheel
        except ImportError:
            raise CommandError(
                "'pip wheel' requires the 'wheel' package. To fix this, run: "
                "pip install wheel"
            )

        try:
            import pkg_resources
        except ImportError:
            raise CommandError(
                "'pip wheel' requires setuptools >= 0.8 for dist-info support."
                " To fix this, run: pip install --upgrade setuptools"
            )
        else:
            if not hasattr(pkg_resources, 'DistInfoDistribution'):
                raise CommandError(
                    "'pip wheel' requires setuptools >= 0.8 for dist-info "
                    "support. To fix this, run: pip install --upgrade "
                    "setuptools"
                )

        index_urls = [options.index_url] + options.extra_index_urls
        if options.no_index:
            logger.info('Ignoring indexes: %s', ','.join(index_urls))
            index_urls = []

        if options.use_mirrors:
            warnings.warn(
                "--use-mirrors has been deprecated and will be removed in the "
                "future. Explicit uses of --index-url and/or --extra-index-url"
                " is suggested.",
                RemovedInPip7Warning,
            )

        if options.mirrors:
            warnings.warn(
                "--mirrors has been deprecated and will be removed in the "
                "future. Explicit uses of --index-url and/or --extra-index-url"
                " is suggested.",
                RemovedInPip7Warning,
            )
            index_urls += options.mirrors

        if options.download_cache:
            warnings.warn(
                "--download-cache has been deprecated and will be removed in "
                "the future. Pip now automatically uses and configures its "
                "cache.",
                RemovedInPip8Warning,
            )

        if options.build_dir:
            options.build_dir = os.path.abspath(options.build_dir)

        with self._build_session(options) as session:

            finder = PackageFinder(
                find_links=options.find_links,
                index_urls=index_urls,
                use_wheel=options.use_wheel,
                allow_external=options.allow_external,
                allow_unverified=options.allow_unverified,
                allow_all_external=options.allow_all_external,
                allow_all_prereleases=options.pre,
                trusted_hosts=options.trusted_hosts,
                process_dependency_links=options.process_dependency_links,
                session=session,
            )

            build_delete = (not (options.no_clean or options.build_dir))
            with BuildDirectory(options.build_dir,
                                delete=build_delete) as build_dir:
                requirement_set = RequirementSet(
                    build_dir=build_dir,
                    src_dir=options.src_dir,
                    download_dir=None,
                    ignore_dependencies=options.ignore_dependencies,
                    ignore_installed=True,
                    isolated=options.isolated_mode,
                    session=session,
                    wheel_download_dir=options.wheel_dir
                )

                # make the wheelhouse
                if not os.path.exists(options.wheel_dir):
                    os.makedirs(options.wheel_dir)

                # parse args and/or requirements files
                for name in args:
                    requirement_set.add_requirement(
                        InstallRequirement.from_line(
                            name, None, isolated=options.isolated_mode,
                        )
                    )
                for name in options.editables:
                    requirement_set.add_requirement(
                        InstallRequirement.from_editable(
                            name,
                            default_vcs=options.default_vcs,
                            isolated=options.isolated_mode,
                        )
                    )
                for filename in options.requirements:
                    for req in parse_requirements(
                            filename,
                            finder=finder,
                            options=options,
                            session=session):
                        requirement_set.add_requirement(req)

                # fail if no requirements
                if not requirement_set.has_requirements:
                    logger.error(
                        "You must give at least one requirement to %s "
                        "(see \"pip help %s\")",
                        self.name, self.name,
                    )
                    return

                try:
                    # build wheels
                    wb = WheelBuilder(
                        requirement_set,
                        finder,
                        options.wheel_dir,
                        build_options=options.build_options or [],
                        global_options=options.global_options or [],
                    )
                    if not wb.build():
                        raise CommandError(
                            "Failed to build one or more wheels"
                        )
                except PreviousBuildDirError:
                    options.no_clean = True
                    raise
                finally:
                    if not options.no_clean:
                        requirement_set.cleanup_files()
