<?php
/**
 * @package     JSpace.Plugin
 *
 * @copyright   Copyright (C) 2014-2015 KnowledgeArc Ltd. All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE
 */

defined('_JEXEC') or die;

/**
 * Authenticates a user using their Twitter credentials, authorizes access to
 * Twitter-based profile information and registers the user details via the
 * Joomla user manager.
 *
 * @package  JSpace.Plugin
 */
class PlgAuthenticationTwitter extends JPlugin
{
    public function __construct(&$subject, $config)
    {
        parent::__construct($subject, $config);
        $this->loadLanguage();
    }

    /**
     * Handles authentication via Twitter and reports back to the subject
     *
     * @param   array   $credentials  Array holding the user credentials
     * @param   array   $options      Array of extra options
     * @param   object  &$response    Authentication response object
     *
     * @return  boolean
     */
    public function onUserAuthenticate($credentials, $options, &$response)
    {
        $response->type = $this->_name;

        if (JArrayHelper::getValue($options, 'action') == 'core.login.site') {
            $username = JArrayHelper::getValue($credentials, 'username');
            $name = JArrayHelper::getValue($credentials, 'name');
            $email = JArrayHelper::getValue($credentials, 'email');

            if (!$username) {
                $response->status = JAuthentication::STATUS_FAILURE;
                $response->error_message = JText::_('JGLOBAL_AUTH_NO_USER');

                return false;
            }

            if ($user = new JUser(JUserHelper::getUserId($username))) {
                if ($user->get('block') || $user->get('activation')) {
                    $response->status = JAuthentication::STATUS_FAILURE;
                    $response->error_message = JText::_('JGLOBAL_AUTH_ACCESS_DENIED');

                    return;
                }
            }

            $response->email = $email;
            $response->fullname = $name;
            $response->username = $username;

            $response->status = JAuthentication::STATUS_SUCCESS;
            $response->error_message = '';
        }
    }

    /**
     * Authenticate the user via the oAuth login and authorize access to the
     * appropriate REST API end-points.
     */
    public function onOauthAuthenticate()
    {
        $oauth = new JTwitterOAuth();

        $oauth->setOption('callback', JUri::current());
        $oauth->setOption('consumer_key', $this->params->get('clientid'));
        $oauth->setOption('consumer_secret', $this->params->get('clientsecret'));
        $oauth->setOption('sendheaders', true);

        $oauth->authenticate();
    }

    /**
     * Swap the authorization code for a persistent token and authorize access
     * to Joomla!.
     *
     * @return  bool  True if the authorization is successful, false otherwise.
     */
    public function onOauthAuthorize()
    {
        $oauth = new JTwitterOAuth();
        $oauth->setOption('consumer_key', $this->params->get('clientid'));
        $oauth->setOption('consumer_secret', $this->params->get('clientsecret'));
        $oauth->setOption('sendheaders', true);
        $oauth->authenticate();

        $twitter = new JTwitter($oauth);

        $token = $twitter->oauth->getToken();

        $settings = $twitter->profile->getSettings();

        // Get the log in credentials.
        $credentials = array();
        $credentials['username']  = $this->_name.'/'.$settings->screen_name;
        $credentials['name'] = $settings->screen_name;

        if (isset($settings->email)) {
            $credentials['email'] = $settings->email;
        } else {
            // we need an email for the auto-register to succeed.
            $credentials['email'] = $settings->screen_name.'@twitter.com';
        }

        $options = array();

        $app = JFactory::getApplication();

        // Perform the log in.
        if (true === $app->login($credentials, $options)) {
            $user = new JUser(JUserHelper::getUserId($credentials['username']));
            $user->setParam('twitter.token.key', JArrayHelper::getValue($token, 'key'));
            $user->setParam('twitter.token.secret', JArrayHelper::getValue($token, 'secret'));
            $user->save();

            return true;
        } else {
            return false;
        }
    }
}
