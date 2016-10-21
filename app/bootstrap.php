<?php

require __DIR__ . '/../vendor/autoload.php';

$configurator = new Nette\Configurator;

if (PHP_SAPI === 'cli') {
	$input = new \Symfony\Component\Console\Input\ArgvInput;
	$env = $input->getParameterOption(['--env', '-e'], getenv('NETTE_ENV') ?: 'dev');
	$debug = getenv('NETTE_DEBUG') !== '0' && !$input->hasParameterOption(['--no-debug', '']) && $env !== 'prod';

	if ($debug) {
		\Symfony\Component\Debug\Debug::enable();
		$configurator->setDebugMode(TRUE);
	}
}

//$configurator->setDebugMode('23.75.345.200'); // enable for your remote IP
$configurator->enableDebugger(__DIR__ . '/../log');

$configurator->setTimeZone('Europe/Prague');
$configurator->setTempDirectory(__DIR__ . '/../temp');

$configurator->addConfig(__DIR__ . '/../config/config.neon');
$configurator->addConfig(__DIR__ . '/../config/config.local.neon');

$container = $configurator->createContainer();

return $container;
