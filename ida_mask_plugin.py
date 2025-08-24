#!/usr/bin/env python3
"""
IDA Mask Plugin - Python Implementation

Provides two menu actions:
- Search by pattern:mask: prompts for pattern:mask input and searches binary
- Create pattern:mask: prompts for assembly code and generates pattern:mask
"""

import ida_idaapi
import ida_kernwin
import ida_funcs
import ida_bytes
import ida_search
import ida_segment


class IDAMaskPlugin(ida_idaapi.plugin_t):
    """Main plugin class for IDA Mask Plugin"""
    
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "IDA Mask Plugin - Pattern search and generation"
    help = "Plugin for searching binary patterns with masks and generating patterns from assembly"
    wanted_name = "IDA Mask Plugin"
    wanted_hotkey = ""

    def init(self):
        """Initialize the plugin"""
        ida_kernwin.msg("[ida_mask_plugin] Initializing plugin...\n")
        
        # Register menu actions
        self.register_actions()
        
        ida_kernwin.msg("[ida_mask_plugin] Plugin initialized successfully\n")
        return ida_idaapi.PLUGIN_KEEP

    def term(self):
        """Terminate the plugin"""
        ida_kernwin.msg("[ida_mask_plugin] Terminating plugin...\n")
        
        # Unregister actions
        self.unregister_actions()
        
        ida_kernwin.msg("[ida_mask_plugin] Plugin terminated\n")

    def run(self, arg):
        """Run the plugin - called when plugin is executed directly"""
        ida_kernwin.msg("[ida_mask_plugin] Plugin run() called with arg: %d\n" % arg)
        
        # Example: List all functions (similar to the C++ example)
        self.list_functions()
        return True

    def register_actions(self):
        """Register menu actions"""
        # Search action
        search_action = ida_kernwin.action_desc_t(
            "ida_mask:search",
            "Search by pattern:mask",
            SearchActionHandler(),
            "",
            "Search binary for pattern with mask",
            -1
        )
        
        # Create action
        create_action = ida_kernwin.action_desc_t(
            "ida_mask:create", 
            "Create pattern:mask",
            CreateActionHandler(),
            "",
            "Generate pattern:mask from assembly code",
            -1
        )
        
        # Register actions
        ida_kernwin.register_action(search_action)
        ida_kernwin.register_action(create_action)
        
        # Attach to menu
        ida_kernwin.attach_action_to_menu(
            "Edit/IDA Mask/Search",
            "ida_mask:search",
            ida_kernwin.SETMENU_APP
        )
        ida_kernwin.attach_action_to_menu(
            "Edit/IDA Mask/Create",
            "ida_mask:create",
            ida_kernwin.SETMENU_APP
        )

    def unregister_actions(self):
        """Unregister menu actions"""
        ida_kernwin.detach_action_from_menu("Edit/IDA Mask/Search", "ida_mask:search")
        ida_kernwin.detach_action_from_menu("Edit/IDA Mask/Create", "ida_mask:create")
        ida_kernwin.unregister_action("ida_mask:search")
        ida_kernwin.unregister_action("ida_mask:create")

    def list_functions(self):
        """Example function listing - similar to C++ version"""
        func_count = ida_funcs.get_func_qty()
        ida_kernwin.msg("[ida_mask_plugin] Found %d functions:\n" % func_count)
        
        for i in range(func_count):
            func = ida_funcs.getn_func(i)
            if func:
                func_name = ida_funcs.get_func_name(func.start_ea)
                if not func_name:
                    func_name = "-UNK-"
                ida_kernwin.msg("Function %s at address 0x%llX\n" % (func_name, func.start_ea))


class SearchActionHandler(ida_kernwin.action_handler_t):
    """Handler for search pattern:mask action"""
    
    def activate(self, ctx):
        """Activate the search action"""
        # Prompt user for pattern:mask input
        pattern_input = ida_kernwin.ask_str("", 0, "Enter pattern:mask (hex:hex)")
        if pattern_input:
            search_pattern_mask(pattern_input)
        return 1

    def update(self, ctx):
        """Update action state"""
        return ida_kernwin.AST_ENABLE_ALWAYS


class CreateActionHandler(ida_kernwin.action_handler_t):
    """Handler for create pattern:mask action"""
    
    def activate(self, ctx):
        """Activate the create action"""
        # Prompt user for assembly input
        asm_input = ida_kernwin.ask_text(0, "", "Enter assembly code (mock)")
        if asm_input:
            create_pattern_from_asm(asm_input)
        return 1

    def update(self, ctx):
        """Update action state"""
        return ida_kernwin.AST_ENABLE_ALWAYS


def search_pattern_mask(input_str):
    """
    Search for pattern with mask in the binary
    
    Args:
        input_str: String in format "pattern:mask" where both are hex strings
                  Example: "1f2003d5090040f9:ffffffff1ffcffff"
    """
    ida_kernwin.msg("[ida_mask_plugin] Search called with pattern: %s\n" % input_str)
    
    try:
        if ':' not in input_str:
            ida_kernwin.warning("Invalid format. Expected pattern:mask (hex:hex)")
            return False
        
        pattern_hex, mask_hex = input_str.split(':', 1)
        pattern_hex = pattern_hex.strip()
        mask_hex = mask_hex.strip()
        
        # Validate hex strings
        if len(pattern_hex) != len(mask_hex):
            ida_kernwin.warning("Pattern and mask must have the same length")
            return False
        
        if len(pattern_hex) % 2 != 0:
            ida_kernwin.warning("Pattern and mask must have even length (complete bytes)")
            return False
        
        # Convert hex strings to bytes
        try:
            pattern_bytes = bytes.fromhex(pattern_hex)
            mask_bytes = bytes.fromhex(mask_hex)
        except ValueError as e:
            ida_kernwin.warning("Invalid hex string: %s" % str(e))
            return False
        
        ida_kernwin.msg("[ida_mask_plugin] Pattern: %s (%d bytes)\n" % (pattern_hex, len(pattern_bytes)))
        ida_kernwin.msg("[ida_mask_plugin] Mask: %s (%d bytes)\n" % (mask_hex, len(mask_bytes)))
        
        # Search in all segments
        results = []
        seg_qty = ida_segment.get_segm_qty()
        for seg_idx in range(seg_qty):
            seg = ida_segment.getnseg(seg_idx)
            if not seg:
                continue
            
            ida_kernwin.msg("[ida_mask_plugin] Searching segment %s (0x%X - 0x%X)\n" % 
                          (ida_segment.get_segm_name(seg), seg.start_ea, seg.end_ea))
            
            # Search within this segment using manual approach
            pattern_len = len(pattern_bytes)
            current_ea = seg.start_ea
            
            while current_ea <= seg.end_ea - pattern_len:
                # Check if current position matches the masked pattern
                if verify_masked_match(current_ea, pattern_bytes, mask_bytes):
                    results.append(current_ea)
                    ida_kernwin.msg("[ida_mask_plugin] Found match at 0x%X\n" % current_ea)
                
                # Move to next byte
                current_ea += 1
        
        # Display results
        if results:
            display_search_results(results, pattern_hex, mask_hex)
            ida_kernwin.info("Found %d matches. See Output window for details." % len(results))
        else:
            ida_kernwin.info("No matches found for pattern: %s" % pattern_hex)
        
        return True
        
    except Exception as e:
        ida_kernwin.warning("Error during search: %s" % str(e))
        return False


def verify_masked_match(address, pattern_bytes, mask_bytes):
    """
    Verify that bytes at address match pattern when masked
    
    Args:
        address: Address to check
        pattern_bytes: Expected pattern bytes
        mask_bytes: Mask bytes (0xFF = must match, 0x00 = ignore)
    
    Returns:
        bool: True if match, False otherwise
    """
    try:
        # Read bytes from memory
        actual_bytes = ida_bytes.get_bytes(address, len(pattern_bytes))
        if not actual_bytes or len(actual_bytes) != len(pattern_bytes):
            return False
        
        # Check each byte with mask
        for i in range(len(pattern_bytes)):
            masked_actual = actual_bytes[i] & mask_bytes[i]
            masked_pattern = pattern_bytes[i] & mask_bytes[i]
            
            if masked_actual != masked_pattern:
                return False
        
        return True
    except:
        return False


def display_search_results(results, pattern_hex, mask_hex):
    """
    Display search results in a formatted way
    
    Args:
        results: List of addresses where pattern was found
        pattern_hex: Original pattern hex string
        mask_hex: Original mask hex string
    """
    ida_kernwin.msg("\n" + "="*60 + "\n")
    ida_kernwin.msg("SEARCH RESULTS\n")
    ida_kernwin.msg("Pattern: %s\n" % pattern_hex)
    ida_kernwin.msg("Mask:    %s\n" % mask_hex)
    ida_kernwin.msg("Found %d matches:\n" % len(results))
    ida_kernwin.msg("-"*60 + "\n")
    
    for i, addr in enumerate(results, 1):
        # Get function name if address is in a function
        func = ida_funcs.get_func(addr)
        func_name = ""
        if func:
            func_name = ida_funcs.get_func_name(func.start_ea)
            func_name = " (%s+0x%X)" % (func_name, addr - func.start_ea)
        
        # Get segment name
        seg = ida_segment.getseg(addr)
        seg_name = ""
        if seg:
            seg_name = ida_segment.get_segm_name(seg)
        
        # Read and display the actual bytes
        actual_bytes = ida_bytes.get_bytes(addr, len(pattern_hex) // 2)
        if actual_bytes:
            actual_hex = actual_bytes.hex().upper()
        else:
            actual_hex = "???"
        
        ida_kernwin.msg("%3d. 0x%08X [%s]%s - %s\n" % 
                       (i, addr, seg_name, func_name, actual_hex))
    
    ida_kernwin.msg("="*60 + "\n")


def create_pattern_from_asm(asm_text):
    """
    Generate pattern:mask from assembly code
    
    Args:
        asm_text: Assembly code as string
    """
    ida_kernwin.msg("[ida_mask_plugin] create_pattern_from_asm called with %d bytes\n" % len(asm_text))
    
    # Mock implementation - just print the input
    ida_kernwin.msg("[ida_mask_plugin] Assembly input:\n%s\n" % asm_text)
    
    # TODO: Implement actual assembly parsing and pattern generation
    # This would involve:
    # 1. Parsing the assembly text
    # 2. Converting to machine code bytes
    # 3. Generating appropriate mask for variable parts (addresses, offsets, etc.)
    # 4. Returning pattern:mask string
    
    ida_kernwin.info("Pattern generation from assembly is not yet implemented.\nInput received:\n%s" % asm_text)
    return True


def PLUGIN_ENTRY():
    """Plugin entry point for IDA Pro"""
    return IDAMaskPlugin()
