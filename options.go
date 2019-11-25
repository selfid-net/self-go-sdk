package selfsdk

// SetEndpoint sets the target endpoint for the self api
func SetEndpoint(target string) func(c *Client) error {
	return func(c *Client) error {
		c.target = target
		return nil
	}
}

// SetMessagingEndpoint sets the target endpoint for self messaging
func SetMessagingEndpoint(target string) func(c *Client) error {
	return func(c *Client) error {
		c.messagingTarget = target
		return nil
	}
}

// SetMessagingDevice sets the messaging device you want to connect as
func SetMessagingDevice(device string) func(c *Client) error {
	return func(c *Client) error {
		c.messagingDevice = device
		return nil
	}
}
