"""RED AGENT - Main Agent Interface

Provides RedAgent class (top-level interface) and RedAgentConfig.
"""

# TODO: Implement RedAgent class and RedAgentConfig
# - RedAgent: Main agent interface with start(), execute_task(), shutdown()
# - RedAgentConfig: Configuration dataclass with pre_shared_key, is_recovery, etc.
# - TaskExecutorFn: Type alias for task executor functions

class RedAgent:
    """Main RED AGENT interface - stub implementation"""
    def __init__(self, config):
        pass
    
    def start(self):
        """Initialize agent through 7-step initialization sequence"""
        pass
    
    def execute_task(self, scope, executor, recipient, need_to_know):
        """Execute a task with output gate authorization"""
        pass
    
    def shutdown(self):
        """Graceful teardown through 7-step teardown sequence"""
        pass


class RedAgentConfig:
    """Agent configuration - stub"""
    def __init__(self, pre_shared_key, is_recovery=False):
        self.pre_shared_key = pre_shared_key
        self.is_recovery = is_recovery
