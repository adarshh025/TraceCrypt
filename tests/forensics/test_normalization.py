"""Unit tests for Forensic Document Normalization pipeline."""

from __future__ import annotations

import numpy as np

from tracecrypt.forensics.normalization import DocumentNormalizer


class TestDocumentNormalizer:
    """Validate deterministic image normalization, channel preparation, and alignment."""

    def test_normalize_grayscale_image(self) -> None:
        # 100x150 image -> aligned to multiple of 16: (96, 144)
        img = np.random.randint(0, 256, (100, 150), dtype=np.uint8)
        norm, tel = DocumentNormalizer.normalize_page(img, deskew_enabled=False)

        assert norm.ndim == 2
        assert norm.dtype == np.uint8
        assert norm.shape[0] % 16 == 0
        assert norm.shape[1] % 16 == 0
        assert norm.shape == (96, 144)
        assert isinstance(tel, dict)
        assert tel["detected_skew_degrees"] == 0.0

    def test_normalize_already_aligned_dimensions(self) -> None:
        img = np.full((256, 256), 200, dtype=np.uint8)
        norm, tel = DocumentNormalizer.normalize_page(img, deskew_enabled=False)
        assert norm.shape == (256, 256)
        assert np.array_equal(norm, img)
        assert tel["normalized_shape"] == [256, 256]

    def test_normalize_rgb_image(self) -> None:
        img_rgb = np.zeros((128, 128, 3), dtype=np.uint8)
        img_rgb[:, :, 0] = 100  # R
        img_rgb[:, :, 1] = 150  # G
        img_rgb[:, :, 2] = 200  # B

        norm, tel = DocumentNormalizer.normalize_page(img_rgb, deskew_enabled=False)
        assert norm.ndim == 2
        assert norm.shape == (128, 128)
        assert tel["initial_shape"] == [128, 128, 3]

    def test_normalize_rgba_image(self) -> None:
        img_rgba = np.full((64, 64, 4), 220, dtype=np.uint8)
        norm, tel = DocumentNormalizer.normalize_page(img_rgba, deskew_enabled=False)
        assert norm.ndim == 2
        assert norm.shape == (64, 64)

    def test_normalize_all_pages(self) -> None:
        p1 = np.ones((128, 128), dtype=np.uint8) * 50
        p2 = np.ones((200, 200), dtype=np.uint8) * 150
        norm_pages, telemetry = DocumentNormalizer.normalize_all_pages([p1, p2], deskew_enabled=False)

        assert len(norm_pages) == 2
        assert len(telemetry) == 2
        assert norm_pages[0].shape == (128, 128)
        assert norm_pages[1].shape == (192, 192)

    def test_target_shape_rescaling(self) -> None:
        img = np.zeros((100, 100), dtype=np.uint8)
        norm, tel = DocumentNormalizer.normalize_page(img, target_shape=(256, 256))
        assert norm.shape == (256, 256)
        assert tel["rescaled_to"] == [256, 256]
