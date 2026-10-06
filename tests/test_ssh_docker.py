"""Pin the out-of-the-box SSH plumbing (spec AC1, plan 0.3)."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_image_ships_ssh_client():
    dockerfile = (ROOT / "Dockerfile").read_text()
    assert "openssh-client" in dockerfile


def test_ssh_volume_mounted_in_compose_files():
    for name in ("docker-compose.yml", "docker-compose.gpu-nvidia.yml",
                 "docker-compose.gpu-amd.yml"):
        text = (ROOT / name).read_text()
        assert "./data/ssh:/app/.ssh" in text, name


def test_entrypoint_ensures_ssh_dir():
    text = (ROOT / "docker" / "entrypoint.sh").read_text()
    assert "/app/data/ssh" in text
