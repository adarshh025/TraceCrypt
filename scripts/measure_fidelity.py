import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests.integration.test_watermark_pipeline import create_sample_pdf
from tracecrypt.document.hasher import DocumentHasher
from tracecrypt.watermark import WatermarkBenchmark, WatermarkParameters

p = create_sample_pdf(1)
h = DocumentHasher.hash_bytes(p)

print("--- Fidelity vs Strength Analysis ---")
for s in [2.0, 4.0, 6.0, 8.0, 10.0, 12.0]:
    b = WatermarkBenchmark.run_performance_benchmark(p, h, params=WatermarkParameters(embedding_strength=s))
    fid = b['fidelity']
    psnr = fid['psnr']
    ssim = fid['ssim']
    status = b['extraction_status']
    print(f"Strength {s:4.1f}: PSNR = {psnr:6.2f} dB, SSIM = {ssim:6.4f}, Status = {status}")
