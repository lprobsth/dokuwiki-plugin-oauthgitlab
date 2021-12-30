<?php

use OAuth\OAuth2\Service\GitLab;
/**
 * Service Implementation for oAuth GitLab authentication
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Lukas Probsthain <lukas.probsthain@gmail.com>
 */
class action_plugin_oauthgitlab extends \dokuwiki\plugin\oauth\Adapter
{

    /** @inheritDoc */
    public function getUser()
    {

    }

    /** @inheritDoc */
    public function getScopes()
    {
        
    }

    /** @inheritDoc */
    public function getLabel()
    {

    }

    public function getColor()
    {
        return '#fc6d27';
    }
}

