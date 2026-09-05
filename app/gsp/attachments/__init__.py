"""Controlled file objects for GSP evidence attachments.

Closes the P0 gap where qualification/authorisation records only kept
client-supplied ``file_ref`` + ``file_sha256`` strings.  This package provides a
real server-side store: files are streamed to a content-addressed directory,
their SHA-256 is computed by the server, the stored object is immutable, and
downloads/verification are permission-controlled and audit-trailed.
"""
