<?php
namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7;
use http\Exception\RuntimeException;
use PHPUnit\Framework\TestCase;

class HashingStreamTest extends TestCase
{
    /**
     * @dataProvider hashAlgorithmProvider
     *
     * @param string $algorithm
     */
    public function testHashShouldMatchThatReturnedByHashMethod($algorithm)
    {
        $toHash = random_bytes(1025);
        $instance = new HashingStream(
            Psr7\Utils::streamFor($toHash),
            null,
            function ($hash) use ($toHash, $algorithm) {
                $this->assertSame(hash($algorithm, $toHash, true), $hash);
            },
            $algorithm
        );

        $instance->getContents();

        $this->assertSame(
            hash($algorithm, $toHash, true),
            $instance->getHash()
        );
    }

    /**
     * @dataProvider hmacAlgorithmProvider
     *
     * @param string $algorithm
     */
    public function testAuthenticatedHashShouldMatchThatReturnedByHashMethod(
        $algorithm
    ) {
        $key = 'secret key';
        $toHash = random_bytes(1025);
        $instance = new HashingStream(
            Psr7\Utils::streamFor($toHash),
            $key,
            function ($hash) use ($toHash, $key, $algorithm) {
                $this->assertSame(
                    hash_hmac($algorithm, $toHash, $key, true),
                    $hash
                );
            },
            $algorithm
        );

        $instance->getContents();

        $this->assertSame(
            hash_hmac($algorithm, $toHash, $key, true),
            $instance->getHash()
        );
    }

    /**
     * @dataProvider hmacAlgorithmProvider
     *
     * @param string $algorithm
     */
    public function testHashingStreamsCanBeRewound($algorithm)
    {
        $key = 'secret key';
        $toHash = random_bytes(1025);
        $callCount = 0;
        $instance = new HashingStream(
            Psr7\Utils::streamFor($toHash),
            $key,
            function ($hash) use ($toHash, $key, $algorithm, &$callCount) {
                ++$callCount;
                $this->assertSame(
                    hash_hmac($algorithm, $toHash, $key, true),
                    $hash
                );
            },
            $algorithm
        );

        $instance->getContents();
        $instance->rewind();
        $instance->getContents();

        $this->assertSame(2, $callCount);
    }

    public function hmacAlgorithmProvider()
    {
        $cryptoHashes = [];
        foreach (hash_hmac_algos() as $algo) {
            if (hash_hmac($algo, 'data', 'secret key')) {
                $cryptoHashes[] = [$algo];
            }
        }
        return $cryptoHashes;
    }

    public function hashAlgorithmProvider()
    {
        return array_map(function ($algo) { return [$algo]; }, hash_algos());
    }

    public function testDoesNotSupportArbitrarySeeking()
    {
        $this->expectException(\LogicException::class);
        $instance = new HashingStream(Psr7\Utils::streamFor(random_bytes(1025)));
        $instance->seek(1);
    }
}
