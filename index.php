<?php
session_start();

/* =========================================================
   WEB VERIFIKATOR DOKUMEN
   SHA-256 + RSA DIGITAL SIGNATURE

   1. Generate pasangan Public Key dan Private Key
   2. Sign dokumen menggunakan Private Key
   3. Verifikasi dokumen menggunakan Public Key
========================================================= */

$defaultDocument  = 'Transfer ke Budi: Rp 100.000';
$modifiedDocument = 'Transfer ke Andi: Rp 100.000';

$message        = '';
$messageType    = '';
$verification   = null;
$verificationHash = '';

/* =========================================================
   FUNGSI MENGAMANKAN OUTPUT HTML
========================================================= */

function e(string $value): string
{
    return htmlspecialchars(
        $value,
        ENT_QUOTES | ENT_SUBSTITUTE,
        'UTF-8'
    );
}

/* =========================================================
   MEMBERSIHKAN ERROR OPENSSL
========================================================= */

function clearOpenSSLErrors(): void
{
    while (openssl_error_string() !== false) {
        // Mengosongkan antrean error OpenSSL.
    }
}

/* =========================================================
   MENGAMBIL ERROR OPENSSL
========================================================= */

function getOpenSSLErrors(): string
{
    $errors = [];

    while (($error = openssl_error_string()) !== false) {
        $errors[] = $error;
    }

    if ($errors === []) {
        return 'Kesalahan OpenSSL tidak diketahui.';
    }

    return implode(' | ', array_unique($errors));
}

/* =========================================================
   MENCARI FILE openssl.cnf PADA LARAGON
========================================================= */

function findOpenSSLConfig(): ?string
{
    $phpDirectory = dirname(PHP_BINARY);
    $laragonRoot  = dirname(dirname(dirname($phpDirectory)));

    $candidates = [
        $phpDirectory . '/extras/ssl/openssl.cnf',
        $phpDirectory . '/openssl.cnf',

        $laragonRoot . '/bin/apache/httpd-*/conf/openssl.cnf',
        $laragonRoot . '/bin/apache/httpd-*/bin/openssl.cnf',

        'C:/laragon/bin/php/php-*/extras/ssl/openssl.cnf',
        'C:/laragon/bin/apache/httpd-*/conf/openssl.cnf',
        'C:/laragon/bin/apache/httpd-*/bin/openssl.cnf',

        'C:/xampp/php/extras/ssl/openssl.cnf',
        'C:/xampp/apache/conf/openssl.cnf',

        '/etc/ssl/openssl.cnf',
        '/usr/lib/ssl/openssl.cnf'
    ];

    foreach ($candidates as $candidate) {

        /*
         * Menangani alamat yang menggunakan tanda bintang.
         */
        if (str_contains($candidate, '*')) {

            $matches = glob($candidate);

            if (!is_array($matches)) {
                continue;
            }

            foreach ($matches as $match) {

                if (is_file($match) && is_readable($match)) {

                    $realPath = realpath($match);

                    return str_replace(
                        '\\',
                        '/',
                        $realPath !== false ? $realPath : $match
                    );
                }
            }

        } elseif (is_file($candidate) && is_readable($candidate)) {

            $realPath = realpath($candidate);

            return str_replace(
                '\\',
                '/',
                $realPath !== false ? $realPath : $candidate
            );
        }
    }

    return null;
}

/* =========================================================
   MENGATUR KONFIGURASI OPENSSL
========================================================= */

function getOpenSSLConfig(): array
{
    $config = [
        'digest_alg'       => 'sha256',
        'private_key_bits' => 2048,
        'private_key_type' => OPENSSL_KEYTYPE_RSA
    ];

    $configPath = findOpenSSLConfig();

    if ($configPath !== null) {

        putenv('OPENSSL_CONF=' . $configPath);
        putenv('SSLEAY_CONF=' . $configPath);

        $config['config'] = $configPath;
    }

    return $config;
}

/* =========================================================
   MENGAMBIL NILAI SESSION
========================================================= */

$publicKey       = $_SESSION['public_key'] ?? '';
$privateKey      = $_SESSION['private_key'] ?? '';
$signedDocument  = $_SESSION['signed_document'] ?? '';
$signedHash      = $_SESSION['signed_hash'] ?? '';
$signatureBase64 = $_SESSION['signature'] ?? '';

/* =========================================================
   MEMPROSES FORM
========================================================= */

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $action = $_POST['action'] ?? '';

    if (!extension_loaded('openssl')) {

        $message =
            'Ekstensi OpenSSL belum aktif pada PHP Laragon.';

        $messageType = 'error';

    } elseif ($action === 'generate_key') {

        /* =================================================
           OPSI 1: GENERATE KEY
        ================================================= */

        clearOpenSSLErrors();

        $config = getOpenSSLConfig();

        $keyPair = openssl_pkey_new($config);

        if ($keyPair === false) {

            $message =
                'Gagal membuat pasangan kunci RSA: '
                . getOpenSSLErrors();

            $messageType = 'error';

        } else {

            $privateKeyPem = '';

            $exportResult = openssl_pkey_export(
                $keyPair,
                $privateKeyPem,
                null,
                $config
            );

            $keyDetails = openssl_pkey_get_details($keyPair);

            if (
                !$exportResult
                || $keyDetails === false
                || !isset($keyDetails['key'])
            ) {

                $message =
                    'Gagal mengambil Public Key atau Private Key: '
                    . getOpenSSLErrors();

                $messageType = 'error';

            } else {

                $publicKey  = $keyDetails['key'];
                $privateKey = $privateKeyPem;

                $_SESSION['public_key']  = $publicKey;
                $_SESSION['private_key'] = $privateKey;

                /*
                 * Menghapus tanda tangan lama karena
                 * pasangan kuncinya sudah berubah.
                 */
                unset(
                    $_SESSION['signed_document'],
                    $_SESSION['signed_hash'],
                    $_SESSION['signature']
                );

                $signedDocument  = '';
                $signedHash      = '';
                $signatureBase64 = '';

                $message =
                    'Pasangan Public Key dan Private Key RSA berhasil dibuat.';

                $messageType = 'success';
            }
        }

    } elseif ($action === 'sign_document') {

        /* =================================================
           OPSI 2: TANDA TANGANI DOKUMEN
        ================================================= */

        $document = (string) ($_POST['document'] ?? '');

        if ($privateKey === '' || $publicKey === '') {

            $message =
                'Generate pasangan kunci terlebih dahulu.';

            $messageType = 'error';

        } elseif (trim($document) === '') {

            $message =
                'Dokumen yang akan ditandatangani tidak boleh kosong.';

            $messageType = 'error';

        } else {

            /*
             * Menghasilkan hash SHA-256 untuk ditampilkan.
             */
            $documentHash = hash('sha256', $document);

            $signatureBinary = '';

            clearOpenSSLErrors();

            /*
             * openssl_sign akan membuat tanda tangan
             * menggunakan Private Key dan SHA-256.
             */
            $signResult = openssl_sign(
                $document,
                $signatureBinary,
                $privateKey,
                OPENSSL_ALGO_SHA256
            );

            if (!$signResult) {

                $message =
                    'Gagal menandatangani dokumen: '
                    . getOpenSSLErrors();

                $messageType = 'error';

            } else {

                $signatureBase64 = base64_encode(
                    $signatureBinary
                );

                $signedDocument = $document;
                $signedHash     = $documentHash;

                $_SESSION['signed_document'] = $signedDocument;
                $_SESSION['signed_hash']     = $signedHash;
                $_SESSION['signature']       = $signatureBase64;

                $message =
                    'Dokumen berhasil ditandatangani menggunakan Private Key.';

                $messageType = 'success';
            }
        }

    } elseif ($action === 'verify_document') {

        /* =================================================
           OPSI 3: VERIFIKASI KEASLIAN
        ================================================= */

        $documentToVerify = (string) (
            $_POST['verify_document'] ?? ''
        );

        $signatureToVerify = trim(
            (string) ($_POST['signature'] ?? '')
        );

        $publicKeyToVerify = trim(
            (string) ($_POST['public_key'] ?? '')
        );

        if ($publicKeyToVerify === '') {

            $message =
                'Public Key belum tersedia. Generate Key terlebih dahulu.';

            $messageType = 'error';

        } elseif ($signatureToVerify === '') {

            $message =
                'Tanda tangan digital belum tersedia. '
                . 'Tandatangani dokumen terlebih dahulu.';

            $messageType = 'error';

        } elseif (trim($documentToVerify) === '') {

            $message =
                'Dokumen yang akan diverifikasi tidak boleh kosong.';

            $messageType = 'error';

        } else {

            $signatureBinary = base64_decode(
                $signatureToVerify,
                true
            );

            if ($signatureBinary === false) {

                $message =
                    'Format tanda tangan Base64 tidak valid.';

                $messageType = 'error';

            } else {

                /*
                 * Menghasilkan hash dokumen yang sedang diperiksa.
                 */
                $verificationHash = hash(
                    'sha256',
                    $documentToVerify
                );

                clearOpenSSLErrors();

                /*
                 * Verifikasi menggunakan Public Key.
                 */
                $verifyResult = openssl_verify(
                    $documentToVerify,
                    $signatureBinary,
                    $publicKeyToVerify,
                    OPENSSL_ALGO_SHA256
                );

                if ($verifyResult === 1) {

                    $verification = true;

                    $message =
                        'DOKUMEN VALID! Dokumen asli dan tanda tangan cocok.';

                    $messageType = 'valid';

                } elseif ($verifyResult === 0) {

                    $verification = false;

                    $message =
                        'DOKUMEN TIDAK VALID! '
                        . 'Dokumen telah dimodifikasi atau tanda tangan tidak cocok.';

                    $messageType = 'invalid';

                } else {

                    $message =
                        'Terjadi kesalahan saat verifikasi: '
                        . getOpenSSLErrors();

                    $messageType = 'error';
                }
            }
        }
    }

    /*
     * Memperbarui data dari session setelah proses selesai.
     */
    $publicKey       = $_SESSION['public_key'] ?? $publicKey;
    $privateKey      = $_SESSION['private_key'] ?? $privateKey;
    $signedDocument  = $_SESSION['signed_document'] ?? $signedDocument;
    $signedHash      = $_SESSION['signed_hash'] ?? $signedHash;
    $signatureBase64 = $_SESSION['signature'] ?? $signatureBase64;
}

/*
 * Nilai awal textarea.
 */
$documentInput = $signedDocument !== ''
    ? $signedDocument
    : $defaultDocument;

$verifyDocumentInput = isset($_POST['verify_document'])
    ? (string) $_POST['verify_document']
    : (
        $signedDocument !== ''
        ? $signedDocument
        : $defaultDocument
    );
?>

<!DOCTYPE html>
<html lang="id">

<head>

    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>Web Verifikator Dokumen</title>

    <style>

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            min-height: 100vh;
            padding: 30px 18px;
            font-family: Arial, Helvetica, sans-serif;
            background: linear-gradient(
                135deg,
                #173f73,
                #315d9c
            );
            color: #172033;
        }

        .container {
            width: 100%;
            max-width: 950px;
            margin: auto;
        }

        .header {
            padding: 28px;
            margin-bottom: 22px;
            border-radius: 18px;
            background: #ffffff;
            text-align: center;
            box-shadow: 0 12px 30px rgba(0, 0, 0, 0.20);
        }

        .header h1 {
            margin: 0 0 8px;
            color: #1d477f;
        }

        .header p {
            margin: 0;
            color: #667085;
        }

        .card {
            margin-bottom: 22px;
            padding: 24px;
            border-radius: 16px;
            background: #ffffff;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.18);
        }

        .card h2 {
            margin: 0 0 8px;
            color: #1d477f;
        }

        .description {
            margin: 0 0 20px;
            color: #667085;
            line-height: 1.6;
        }

        label {
            display: block;
            margin: 15px 0 8px;
            font-weight: bold;
        }

        textarea {
            width: 100%;
            min-height: 105px;
            padding: 13px;
            border: 1px solid #c8d0dc;
            border-radius: 10px;
            resize: vertical;
            font-family: Consolas, monospace;
            font-size: 14px;
        }

        textarea:focus {
            outline: none;
            border-color: #2868b2;
            box-shadow: 0 0 0 3px rgba(40, 104, 178, 0.15);
        }

        .key-output {
            min-height: 170px;
            color: #eaf1ff;
            background: #17263c;
        }

        button {
            width: 100%;
            margin-top: 15px;
            padding: 13px;
            border: none;
            border-radius: 10px;
            background: #1677f2;
            color: #ffffff;
            font-size: 15px;
            font-weight: bold;
            cursor: pointer;
        }

        button:hover {
            background: #0d63d0;
        }

        .sign-button {
            background: #25a847;
        }

        .sign-button:hover {
            background: #1d8e3b;
        }

        .verify-button {
            background: #ec9a16;
        }

        .verify-button:hover {
            background: #cf8010;
        }

        .small-buttons {
            display: flex;
            gap: 10px;
            margin-top: 10px;
        }

        .small-buttons button {
            width: auto;
            flex: 1;
            margin-top: 0;
            font-size: 13px;
        }

        .original-button {
            background: #52677e;
        }

        .modified-button {
            background: #dc3545;
        }

        .alert {
            margin-bottom: 22px;
            padding: 17px;
            border-left: 6px solid;
            border-radius: 10px;
            line-height: 1.6;
            background: #ffffff;
        }

        .success {
            color: #176b32;
            border-color: #28a745;
            background: #eaf8ef;
        }

        .error {
            color: #8c1d25;
            border-color: #dc3545;
            background: #fff0f1;
        }

        .valid {
            color: #176b32;
            border-color: #28a745;
            background: #e5f8ec;
            font-weight: bold;
        }

        .invalid {
            color: #8c1d25;
            border-color: #dc3545;
            background: #fff0f1;
            font-weight: bold;
        }

        .hash-box {
            margin-top: 16px;
            padding: 14px;
            border-radius: 9px;
            background: #f1f5fa;
            overflow-wrap: anywhere;
            line-height: 1.6;
        }

        .hash-box strong {
            color: #1d477f;
        }

        .key-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 18px;
            margin-top: 20px;
        }

        .warning {
            margin-top: 14px;
            padding: 13px;
            border-radius: 8px;
            color: #725400;
            background: #fff7d6;
            line-height: 1.6;
        }

        .result-title {
            font-size: 22px;
        }

        @media (max-width: 700px) {

            .key-grid {
                grid-template-columns: 1fr;
            }

            .small-buttons {
                flex-direction: column;
            }
        }

    </style>

</head>

<body>

<div class="container">

    <header class="header">

        <h1>Web Verifikator Dokumen</h1>

        <p>
            SHA-256 Hash dan RSA Digital Signature dengan OpenSSL PHP
        </p>

    </header>

    <?php if ($message !== ''): ?>

        <div class="alert <?= e($messageType) ?>">

            <?= e($message) ?>

        </div>

    <?php endif; ?>

    <!-- ==================================================
         OPSI 1: GENERATE KEY
    =================================================== -->

    <section class="card">

        <h2>1. Generate Key</h2>

        <p class="description">
            Membuat pasangan Public Key dan Private Key RSA 2048 bit.
        </p>

        <form method="POST">

            <input
                type="hidden"
                name="action"
                value="generate_key"
            >

            <button type="submit">
                Generate Public Key & Private Key
            </button>

        </form>

        <?php if ($publicKey !== '' && $privateKey !== ''): ?>

            <div class="key-grid">

                <div>

                    <label>Public Key</label>

                    <textarea
                        class="key-output"
                        readonly
                    ><?= e($publicKey) ?></textarea>

                </div>

                <div>

                    <label>Private Key</label>

                    <textarea
                        class="key-output"
                        readonly
                    ><?= e($privateKey) ?></textarea>

                </div>

            </div>

            <div class="warning">
                Private Key ditampilkan hanya untuk kebutuhan praktikum.
                Pada sistem nyata, Private Key harus dirahasiakan.
            </div>

        <?php endif; ?>

    </section>

    <!-- ==================================================
         OPSI 2: SIGN
    =================================================== -->

    <section class="card">

        <h2>2. Tanda Tangani Dokumen</h2>

        <p class="description">
            Dokumen dibuatkan hash SHA-256 dan ditandatangani
            menggunakan Private Key.
        </p>

        <form method="POST">

            <input
                type="hidden"
                name="action"
                value="sign_document"
            >

            <label for="document">
                Dokumen asli
            </label>

            <textarea
                id="document"
                name="document"
                required
            ><?= e($documentInput) ?></textarea>

            <button
                type="submit"
                class="sign-button"
            >
                Tanda Tangani dengan Private Key
            </button>

        </form>

        <?php if ($signatureBase64 !== ''): ?>

            <div class="hash-box">

                <strong>Hash SHA-256 Dokumen Asli:</strong>

                <br>

                <?= e($signedHash) ?>

            </div>

            <label>Tanda Tangan Digital Base64</label>

            <textarea readonly><?= e($signatureBase64) ?></textarea>

        <?php endif; ?>

    </section>

    <!-- ==================================================
         OPSI 3: VERIFIKASI
    =================================================== -->

    <section class="card">

        <h2>3. Verifikasi Keaslian</h2>

        <p class="description">
            Verifikasi dilakukan menggunakan dokumen,
            tanda tangan digital, dan Public Key.
        </p>

        <form method="POST">

            <input
                type="hidden"
                name="action"
                value="verify_document"
            >

            <label for="verify_document">
                Dokumen yang akan diverifikasi
            </label>

            <textarea
                id="verify_document"
                name="verify_document"
                required
            ><?= e($verifyDocumentInput) ?></textarea>

            <div class="small-buttons">

                <button
                    type="button"
                    class="original-button"
                    onclick="useOriginalDocument()"
                >
                    Gunakan Dokumen Asli
                </button>

                <button
                    type="button"
                    class="modified-button"
                    onclick="useModifiedDocument()"
                >
                    Simulasi Budi Menjadi Andi
                </button>

            </div>

            <label for="signature">
                Tanda Tangan Digital Base64
            </label>

            <textarea
                id="signature"
                name="signature"
                required
            ><?= e($signatureBase64) ?></textarea>

            <label for="public_key">
                Public Key
            </label>

            <textarea
                id="public_key"
                name="public_key"
                class="key-output"
                required
            ><?= e($publicKey) ?></textarea>

            <button
                type="submit"
                class="verify-button"
            >
                Verifikasi Keaslian Dokumen
            </button>

        </form>

        <?php if ($verification !== null): ?>

            <div
                class="alert <?= $verification ? 'valid' : 'invalid' ?>"
                style="margin-top: 20px; margin-bottom: 0;"
            >

                <div class="result-title">

                    <?php if ($verification): ?>

                        ✓ DOKUMEN VALID / ASLI

                    <?php else: ?>

                        ✕ DOKUMEN TIDAK VALID / DIMODIFIKASI

                    <?php endif; ?>

                </div>

            </div>

            <div class="hash-box">

                <strong>Hash dokumen saat ditandatangani:</strong>

                <br>

                <?= e($signedHash) ?>

                <br><br>

                <strong>Hash dokumen saat diverifikasi:</strong>

                <br>

                <?= e($verificationHash) ?>

            </div>

        <?php endif; ?>

    </section>

</div>

<script>

    const originalDocument =
        <?= json_encode(
            $defaultDocument,
            JSON_UNESCAPED_UNICODE
            | JSON_UNESCAPED_SLASHES
        ) ?>;

    const modifiedDocument =
        <?= json_encode(
            $modifiedDocument,
            JSON_UNESCAPED_UNICODE
            | JSON_UNESCAPED_SLASHES
        ) ?>;

    function useOriginalDocument()
    {
        document.getElementById(
            'verify_document'
        ).value = originalDocument;
    }

    function useModifiedDocument()
    {
        document.getElementById(
            'verify_document'
        ).value = modifiedDocument;
    }

</script>

</body>
</html>