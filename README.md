# Elliptic Curve Cryptography (ECC) Core

Proyek C++ ringkas untuk mempelajari aljabar kurva eliptik sekaligus mencoba operasi kriptografi yang disediakan OpenSSL 3.

## Fitur

- Aritmetika titik pada kurva `y² = x³ + ax + b (mod p)`, termasuk titik identitas, point addition, point doubling, dan perkalian skalar melalui `Point + Point` serta `k * Point`.
- Pembuatan pasangan kunci kurva P-256 (`prime256v1`).
- Tanda tangan dan verifikasi ECDSA-SHA256.
- Contoh envelope enkripsi: ECDH ephemeral, HKDF-SHA256, dan AES-256-GCM.
- Demo CLI dan self-test yang menguji round-trip, tanda tangan, serta penolakan ciphertext yang diubah.

## Matematika singkat

Di atas medan prima `F_p`, titik-titik memenuhi `y² ≡ x³ + ax + b (mod p)`. Jika `P != Q`, kemiringan garis adalah `m = (y₂-y₁)/(x₂-x₁) mod p`; untuk menggandakan titik, `m = (3x₁²+a)/(2y₁) mod p`. Hasilnya `x₃ = m²-x₁-x₂` dan `y₃ = m(x₁-x₃)-y₁`, seluruhnya modulo `p`. Perkalian skalar `kP` mengulang penjumlahan titik; keamanan sistem ECC modern bertumpu pada sulitnya menemukan `k` dari `P` dan `kP` (Elliptic-Curve Discrete Logarithm Problem).

Implementasi `educational::Point` memakai kurva mainan `F_17` pada demo agar perhitungan dapat diikuti. Contoh ini **bukan** parameter yang aman untuk kriptografi.

Konstruktor `Point` mensyaratkan `p > 3` dan menjalankan uji Miller–Rabin *probable prime* (hingga 32 ronde untuk kandidat besar) untuk menolak modulus komposit. Itu bukan bukti matematis; pemanggil tetap harus memasok modulus prima yang diketahui. Invers modular memakai Teorema Kecil Fermat, yang hanya berlaku untuk modulus prima.

## Build dan jalankan

Prasyarat: C++17 atau lebih baru, Boost headers, OpenSSL 3 beserta header pengembangan (`libssl-dev` pada Debian/Ubuntu), dan `make`.

```bash
make
./build/ecc_demo
make test
```

Hasil build diletakkan di `build/`. Program demo memperlihatkan `2P`, melakukan enkripsi/dekripsi contoh, lalu menandatangani pesan dan memverifikasi tanda tangannya.

## Batas keamanan penting

- Aritmetika `educational::Point` dan perkalian skalar double-and-add **tidak constant-time**. Implementasi memakai `boost::multiprecision::cpp_int`, yang tidak menjanjikan waktu eksekusi konstan. Jangan pernah memakai kelas ini pada private key, secret scalar, atau data produksi.
- Operasi kunci, ECDH, ECDSA, HKDF, dan AES-GCM di contoh produksi didelegasikan ke OpenSSL; proyek ini bukan implementasi primitif kriptografi independen atau audit keamanan.
- Untuk mengurangi risiko timing side-channel, contoh tidak menjalankan private key atau secret scalar melalui kelas titik edukatif; operasi rahasia memakai API EVP OpenSSL. Jaminan aktual tetap bergantung pada versi, provider, platform, dan konfigurasi OpenSSL—proyek ini tidak mengklaim sertifikasi constant-time.
- Kombinasi ECDH/HKDF/AES-GCM di sini adalah envelope demonstrasi, bukan protokol standar yang diaudit secara independen. Untuk aplikasi nyata gunakan protokol dan pustaka yang ditinjau pakar; lakukan pengelolaan kunci, rotasi, dan autentikasi identitas dengan benar.
- API contoh menerima kunci publik dalam format titik SEC1 tak terkompresi yang diekspor OpenSSL. Penyimpanan kunci privat dan format pesan lintas sistem tidak termasuk.
- Panjang input yang diteruskan ke API OpenSSL bertipe `int` ditolak bila melampaui `INT_MAX`; penjumlahan ukuran buffer juga diperiksa agar tidak overflow.

## Struktur

```text
include/ecc/       API aritmetika edukatif dan kripto OpenSSL
src/               implementasi dan demo
tests/              self-test mandiri
```

## Lisensi

MIT — lihat [LICENSE](LICENSE).
