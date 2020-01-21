package selfsdk

import "time"

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

// AutoReconnect enables or disables automatic reconnection to the messaging endpoint
func AutoReconnect(enabled bool) func(c *Client) error {
	return func(c *Client) error {
		c.reconnect = enabled
		return nil
	}
}

// SetQRColors sets the colors of the qr code
func SetQRColors(foreground, background string) func(c *qrConfig) error {
	return func(c *qrConfig) error {
		c.qrcolorf = foreground
		c.qrcolorb = background
		return nil
	}
}

// SetQRSize sets the size of the QR Code
func SetQRSize(size int) func(c *qrConfig) error {
	return func(c *qrConfig) error {
		c.size = size
		return nil
	}
}

// SetQRExpiry sets the expiry on the QR Code
func SetQRExpiry(exp time.Duration) func(c *qrConfig) error {
	return func(c *qrConfig) error {
		c.expiry = exp
		return nil
	}
}

// SetQRFields sets fields within the QR Code
func SetQRFields(fields map[string]interface{}) func(c *qrConfig) error {
	return func(c *qrConfig) error {
		c.fields = fields
		return nil
	}
}
