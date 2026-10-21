"""Resolver management for the Debian edition.

The engage/restore discipline (the fleet's Charon-toll rule applied
to DNS): the filter proves it answers before the machine's resolver
is pointed at it; the original configuration is saved and read-back
verified before any change and never overwritten; restore is exact.
:class:`~sphinx_deb.resolver.guard.DnsGuard` owns the discipline;
:class:`~sphinx_deb.resolver.systemview.ResolverView` is the seam to
the real machine, so the whole discipline is testable on fakes.
"""
