<?php

use dokuwiki\plugin\oauth\Adapter;
use dokuwiki\plugin\oauthgitlab\Gitlab;

/**
 * Service Implementation for oAuth GitLab authentication
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Lukas Probsthain <lukas.probsthain@gmail.com>
 */
class action_plugin_oauthgitlab extends \dokuwiki\plugin\oauth\Adapter
{
    /** @inheritdoc */
    public function registerServiceClass()
    {
        return Gitlab::class;
    }

    protected $gitlabUserData = null;
    
    protected $gitlabUserApiData = [];

    /** @inheritDoc */
    public function getUser()
    {
        dbglog('Check User');
        $oauth = $this->getOAuthService();

        $data = array();

        $result = $this->getGitlabUserData();
        $data['user'] = $result['username'];
        $data['name'] = $result['name'];
        $data['mail'] = $result['email'];

        return $data;
    }

    /** @inheritDoc */
    public function getScopes()
    {
        return array('read_user','api');
    }

    /** @inheritDoc */
    public function getLabel()
    {
        return 'GitLab';
    }

    public function getColor()
    {
        return '#fc6d27';
    }
    protected function getGitlabUserData() {
        $oauth = $this->getOAuthService();

        if (null !== $this->gitlabUserData) {
            return $this->gitlabUserData;
        }
        
        $this->gitlabUserData = json_decode($oauth->request('user'), true);
        
        return $this->gitlabUserData;
    }
    
    protected function getGitlabUserGroups() {
        if (isset($this->gitlabUserApiData['group'])) {
            return $this->gitlabUserApiData['group'];
        }
        
        $groups = [];
        foreach(json_decode($this->oAuth->request('groups'), true) as $group) {
            $groups[$group['path']] = $group;
        }
        
        $this->gitlabUserApiData['group'] = $groups;
        
        return $groups;
    }

    protected function getGitlabUserProjects() {
        if (isset($this->gitlabUserApiData['projects'])) {
            return $this->gitlabUserApiData['projects'];
        }
        
        $projects = [];
        foreach(json_decode($this->oAuth->request('projects'), true) as $project) {
            $projects[$project['path']] = $project;
        }
        
        $this->gitlabUserApiData['projects'] = $projects;
        
        return $projects;
    }

    public function checkMatchRules() {
        
        /** @var helper_plugin_oauth $hlp */
        $hlp     = plugin_load('helper', 'oauthgitlab');
        
        if (!$rules = trim($hlp->getConf('rules'))) {
            return true;
        }
        
        $rules = explode("\n", $rules);
        
        $namespacedDataFunctions = [
            'user' => [$this, 'getGitlabUserData'],
            'groups' => [$this, 'getGitlabUserGroups'],
            'projects' => [$this, 'getGitlabUserProjects'],
        ];
        
        foreach ($rules as $rule) {
            $rule = trim($rule);
            if (!$rule || substr($rule, 0, 1) === '#') {
                continue;
            }
            
            // ns/key/subkey/subsubkey.. [ (!=|=) value ]
            if (!preg_match('#^\s*([a-z-_]+)/([a-z-_/\s]+)\s*(?:(!?=)\s*(.+))?$#i', $rule, $match)) {
                dbglog('Wrong gitlab rule format '.$rule.'. Ignoring.');
                continue;
            }
            
            $ns = $match[1];
            if (!isset($namespacedDataFunctions[$ns])) {
                dbglog('Unknow gitlab rule namespace '.$ns.' in rule "'.$rule.'". Ignoring.');
                continue;
            }
            
            $nsData = call_user_func($namespacedDataFunctions[$ns]);
            $fullKey = $match[2];
            $existOnly = empty($match[3]);
            
            $targetValue = $nsData;
            foreach (explode('/', $fullKey) as $key) {
                if ('' === $key) {
                    return $targetValue;
                }
                
                if (array_key_exists($key, $targetValue)) {
                    $targetValue = $targetValue[$key];
                } else {
                    $targetValue = null;
                    break;
                }
            }
            
            if (!$existOnly) {
                $isNot = ($match[3] == '!='); // else equal to "="
                $value = $match[4];
                $ruleCheck = ( ($targetValue == $value) xor $isNot );
            } else {
                $ruleCheck = null !== $targetValue;
            }
            
            if (!$ruleCheck) {
                //dbglog('User does not validate rule "'.$rule.'"');
                return false;
            }
        }
        
        return true;
    }
    
    public function checkToken() {
        if (!parent::checkToken()) {
            return false;
        }
        
        return $this->checkMatchRules();
    }

    /**
     * @inheritdoc
     * @throws \OAuth\Common\Exception\Exception
     */
    public function logout()
    {
        /** @var Gitlab */
        $oauth = $this->getOAuthService();
        $oauth->logout();
    }
}

