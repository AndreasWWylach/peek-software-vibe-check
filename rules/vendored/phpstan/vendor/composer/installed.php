<?php return array(
    'root' => array(
        'name' => 'vibe-check/phpstan-extensions',
        'pretty_version' => '1.0.0+no-version-set',
        'version' => '1.0.0.0',
        'reference' => NULL,
        'type' => 'library',
        'install_path' => __DIR__ . '/../../',
        'aliases' => array(),
        'dev' => false,
    ),
    'versions' => array(
        'phpstan/phpstan' => array(
            'dev_requirement' => false,
            'replaced' => array(
                0 => '2.3.1',
            ),
        ),
        'phpstan/phpstan-doctrine' => array(
            'pretty_version' => '2.1.2',
            'version' => '2.1.2.0',
            'reference' => '54d759477ffdd095facf2d193fc91ad7a6733c6a',
            'type' => 'phpstan-extension',
            'install_path' => __DIR__ . '/../phpstan/phpstan-doctrine',
            'aliases' => array(),
            'dev_requirement' => false,
        ),
        'phpstan/phpstan-symfony' => array(
            'pretty_version' => '2.1.1',
            'version' => '2.1.1.0',
            'reference' => 'e218a49b5d24c9fd74903e22433fb10e16c33a53',
            'type' => 'phpstan-extension',
            'install_path' => __DIR__ . '/../phpstan/phpstan-symfony',
            'aliases' => array(),
            'dev_requirement' => false,
        ),
        'vibe-check/phpstan-extensions' => array(
            'pretty_version' => '1.0.0+no-version-set',
            'version' => '1.0.0.0',
            'reference' => NULL,
            'type' => 'library',
            'install_path' => __DIR__ . '/../../',
            'aliases' => array(),
            'dev_requirement' => false,
        ),
    ),
);
