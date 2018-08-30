<?php

namespace TrustedTimestamps\Test\TestCase;

use PHPUnit\Framework\TestCase;
use TrustedTimestamps\TrustedTimestamps;

class XsdToArrayTest extends TestCase
{
    const TSA_URL = 'http://zeitstempel.dfn.de';

    private $toUnlink = array();

    public function testAll()
    {
        $sha1 = sha1('foo');
        /** @var \PHPUnit\Framework\string|string $requestFile (suppress IDE warning) */
        $requestFile = TrustedTimestamps::createRequestfile($sha1);
        $this->assertFileExists($requestFile);
        $this->toUnlink[] = $requestFile;

        $signature = TrustedTimestamps::signRequestfile($requestFile, self::TSA_URL);
        $this->assertTrue(!empty($signature));
        $this->assertTrue(!empty($signature['response_string']));

        $timestamp = TrustedTimestamps::getTimestampFromAnswer($signature['response_string']);
        $this->assertTrue(!empty($timestamp));
    }

    public function tearDown()
    {
        parent::tearDown();
        foreach ($this->toUnlink as $file) {
            unlink($file);
        }
    }
}