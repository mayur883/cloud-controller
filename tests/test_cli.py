"""
Tests for Laboratory Cloud Controller CLI tool (`labcloud`).
"""

import pytest
import os
import io
import tempfile
from pathlib import Path
from unittest.mock import patch

from cloud_controller.cli import (
    cmd_login,
    cmd_upload,
    cmd_list,
    cmd_download,
    cmd_blocks,
    cmd_quota,
    cmd_cluster,
    cmd_publish,
    load_session,
)


class Args:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


def test_cli_lifecycle_end_to_end(capsys):
    # 1. Test Login
    login_args = Args(username="alice", password="labpassword123", server="http://testserver")
    
    # We can mock requests session against TestClient
    from fastapi.testclient import TestClient
    from cloud_controller.api import app
    client = TestClient(app)

    with patch("requests.post", side_effect=client.post), \
         patch("requests.get", side_effect=client.get), \
         patch("requests.delete", side_effect=client.delete):
        
        # Login
        cmd_login(login_args)
        captured = capsys.readouterr()
        assert "Successfully authenticated as 'alice'" in captured.out
        
        session = load_session()
        assert session is not None
        assert session["token"] is not None

        # Upload
        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".txt") as tf:
            tf.write("Sample test payload for CLI end-to-end verification")
            tf_path = tf.name

        try:
            up_args = Args(filepath=tf_path, block_size=65536, no_encrypt=False)
            cmd_upload(up_args)
            captured = capsys.readouterr()
            assert "File uploaded successfully!" in captured.out
            assert "AES-256-GCM" in captured.out

            # List
            list_args = Args()
            cmd_list(list_args)
            captured = capsys.readouterr()
            assert "Laboratory Files" in captured.out
            assert Path(tf_path).name[:10] in captured.out

            # Quota
            quota_args = Args()
            cmd_quota(quota_args)
            captured = capsys.readouterr()
            assert "Storage Quota Status" in captured.out
            assert "alice" in captured.out

            # Cluster
            cluster_args = Args()
            cmd_cluster(cluster_args)
            captured = capsys.readouterr()
            assert "Apache HDFS Cluster Health" in captured.out
            assert "dn-rack1-01" in captured.out

        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)
