<?php
/**
 * Options for the oauthgitlab plugin
 *
 * @author Lukas Probsthain <lukas.probsthain@gmail.com>
 */

$meta['url'] = array('string');
$meta['key'] = array('string');
$meta['secret'] = ['password'];
$meta['rules'] = array('string','_caution' => 'warning');