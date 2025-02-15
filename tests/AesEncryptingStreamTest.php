<?php
namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\StreamInterface;
use function PHPUnit\Framework\throwException;

class AesEncryptingStreamTest extends TestCase
{
    const KB = 1024;
    const MB = 1048576;
    const KEY = 'foo';

    use AesEncryptionStreamTestTrait;

    /**
     * @dataProvider cartesianJoinInputCipherMethodProvider
     *
     * @param StreamInterface $plainTextStream
     * @param string $plainText
     * @param CipherMethod $iv
     */
    public function testStreamOutputSameAsOpenSSL(
        StreamInterface $plainTextStream,
        string $plainText,
        CipherMethod $iv
    ) {
        $this->assertSame(
            openssl_encrypt(
                $plainText,
                $iv->getOpenSslName(),
                self::KEY,
                OPENSSL_RAW_DATA,
                $iv->getCurrentIv()
            ),
            (string) new AesEncryptingStream(
                $plainTextStream,
                self::KEY,
                $iv
            )
        );
    }

    /**
     * @dataProvider cartesianJoinInputCipherMethodProvider
     *
     * @param StreamInterface $plainTextStream
     * @param string $plainText
     * @param CipherMethod $iv
     */
    public function testSupportsReadingBeyondTheEndOfTheStream(
        StreamInterface $plainTextStream,
        string $plainText,
        CipherMethod $iv
    ) {
        $cipherText = openssl_encrypt(
            $plainText,
            $iv->getOpenSslName(),
            self::KEY,
            OPENSSL_RAW_DATA,
            $iv->getCurrentIv()
        );
        $cipherStream = new AesEncryptingStream($plainTextStream, self::KEY, $iv);
        $this->assertSame($cipherText, $cipherStream->read(strlen($plainText) + self::MB));
        $this->assertSame('', $cipherStream->read(self::MB));
    }

    /**
     * @dataProvider cartesianJoinInputCipherMethodProvider
     *
     * @param StreamInterface $plainTextStream
     * @param string $plainText
     * @param CipherMethod $iv
     */
    public function testSupportsRewinding(
        StreamInterface $plainTextStream,
        string $plainText,
        CipherMethod $iv
    ) {
        if (!$plainTextStream->isSeekable()) {
            $this->markTestSkipped('Cannot rewind encryption streams whose plaintext is not seekable');
        } else {
            $cipherText = new AesEncryptingStream($plainTextStream, 'foo', $iv);
            $firstBytes = $cipherText->read(256 * 2 + 3);
            $cipherText->rewind();
            $this->assertSame($firstBytes, $cipherText->read(256 * 2 + 3));
        }
    }

    /**
     * @dataProvider cartesianJoinInputCipherMethodProvider
     *
     * @param StreamInterface $plainTextStream
     * @param string $plainText
     * @param CipherMethod $iv
     */
    public function testAccuratelyReportsSizeOfCipherText(
        StreamInterface $plainTextStream,
        string $plainText,
        CipherMethod $iv
    ) {
        if ($plainTextStream->getSize() === null) {
            $this->markTestSkipped('Cannot read size of ciphertext stream when plaintext stream size is unknown');
        } else {
            $cipherText = new AesEncryptingStream($plainTextStream, 'foo', $iv);
            $this->assertSame($cipherText->getSize(), strlen((string) $cipherText));
        }
    }

    /**
     * @dataProvider cipherMethodProvider
     *
     * @param CipherMethod $cipherMethod
     */
    public function testMemoryUsageRemainsConstant(CipherMethod $cipherMethod)
    {
        $memory = memory_get_usage();

        $stream = new AesEncryptingStream(
            new RandomByteStream(124 * self::MB),
            'foo',
            $cipherMethod
        );

        while (!$stream->eof()) {
            $stream->read(self::MB);
        }

        // Reading 1MB chunks should take 2MB
        $this->assertLessThanOrEqual($memory + 2 * self::MB, memory_get_usage());
    }

    public function testIsNotWritable()
    {
        $stream = new AesEncryptingStream(
            new RandomByteStream(124 * self::MB),
            'foo',
            new Cbc(random_bytes(openssl_cipher_iv_length('aes-256-cbc')))
        );

        $this->assertFalse($stream->isWritable());
    }

    /**
     * @dataProvider cipherMethodProvider
     *
     * @param CipherMethod $cipherMethod
     */
    public function testReturnsPaddedOrEmptyStringWhenSourceStreamEmpty(
        CipherMethod $cipherMethod
    ){
        $stream = new AesEncryptingStream(
            Psr7\Utils::streamFor(''),
            'foo',
            $cipherMethod
        );

        $paddingLength = $cipherMethod->requiresPadding() ? AesEncryptingStream::BLOCK_SIZE : 0;

        $this->assertSame($paddingLength, strlen($stream->read(self::MB)));
        $this->assertSame($stream->read(self::MB), '');
    }

    /**
     * @dataProvider cipherMethodProvider
     *
     * @param CipherMethod $cipherMethod
     *
     *
     */
    public function testDoesNotSupportSeekingFromEnd(CipherMethod $cipherMethod)
    {
        $this->expectException(\LogicException::class);
        $stream = new AesEncryptingStream(Psr7\Utils::streamFor('foo'), 'foo', $cipherMethod);

        $stream->seek(1, SEEK_END);
    }

    /**
     * @dataProvider seekableCipherMethodProvider
     *
     * @param CipherMethod $cipherMethod
     */
    public function testSupportsSeekingFromCurrentPosition(
        CipherMethod $cipherMethod
    ){
        $stream = new AesEncryptingStream(
            Psr7\Utils::streamFor(random_bytes(2 * self::MB)),
            'foo',
            $cipherMethod
        );

        $lastFiveBytes = substr($stream->read(self::MB), self::MB - 5);
        $stream->seek(-5, SEEK_CUR);
        $this->assertSame($lastFiveBytes, $stream->read(5));
    }
    public function testEmitsErrorWhenEncryptionFails()
    {
        set_error_handler(function ($_, $message) use (&$error) {
            $error = $message;
        });

        if (PHP_VERSION_ID > 70400) {
            $this->expectException(EncryptionFailedException::class);
        }

        $_ = (string) new AesEncryptingStream(new RandomByteStream(self::MB), self::KEY,
            new class implements CipherMethod {
                public function getCurrentIv(): string { return 'iv'; }

                public function getOpenSslName(): string { return 'aes-157-cbd'; }

                public function requiresPadding(): bool { return false; }

                public function update(string $cipherTextBlock): void {}

                public function seek(int $offset, int $whence = SEEK_SET): void {}
            });

        $this->assertRegExp('/EncryptionFailedException: Unable to encrypt/', $error);
    }

    public function testSupportsReadLength1()
    {
        $key = "keyy";
        $plain = str_repeat("a", 49);
        $iv = hex2bin("5dfe91624ede1efc6bc1c90e1932c398");

        $cipherMethod = new Cbc($iv, $keySize=128);
        $e = new AesEncryptingStream(Psr7\Utils::streamFor($plain), $key, $cipherMethod);

        $result = "";
        for ($i = 0; $i < 100; $i++) {
            $result .= $e->read(1);
        }

        $this->assertEquals(64, strlen($result));
    }
}
