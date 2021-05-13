<?php

namespace ivol\Workday\Request;

class Loader
{
    public static function load()
    {
        $requestFileName = __DIR__ . '/example.req';
        return file_get_contents($requestFileName);
    }
}