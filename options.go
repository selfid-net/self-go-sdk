package selfsdk

import "time"

// WithBaseURL sets the endpoint for the Self API.
func WithBaseURL(baseURL string) func(c *Client) error {
	return func(c *Client) error {
		c.baseURL = baseURL
		return nil
	}
}

// WithMessagingURL sets the endpoint for the Self Messaging service.
func WithMessagingURL(messagingURL string) func(c *Client) error {
	return func(c *Client) error {
		c.messagingURL = messagingURL
		return nil
	}
}

// WithMessagingDevice sets the messaging device you want to connect as.
func WithMessagingDevice(device string) func(c *Client) error {
	return func(c *Client) error {
		c.messagingDevice = device
		return nil
	}
}

// WithAutoReconnect enables or disables automatic reconnection to the messaging endpoint.
func WithAutoReconnect(enabled bool) func(c *Client) error {
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
