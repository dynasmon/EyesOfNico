package monitor

// A single worker bounds both cached slow collection and any blocked host API.
func (c *Collector) slowWorker() {
	for {
		select {
		case <-c.stop:
			return
		case <-c.slowRequest:
		}
		result := c.collectSlow()
		select {
		case <-c.stop:
			return
		case c.slowResult <- result:
		}
	}
}
