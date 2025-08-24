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
import idaapi
import idc


def get_selected_disassembly():
    """Get raw disassembly from selected lines in IDA by disassembling bytecode without symbols"""
    try:
        # Get the current selection
        selection_start = idc.read_selection_start()
        selection_end = idc.read_selection_end()
        
        if selection_start == idaapi.BADADDR or selection_end == idaapi.BADADDR:
            return ""
        
        # Collect raw assembly by disassembling the actual bytes using Capstone
        disasm_lines = []
        current_ea = selection_start
        
        # Try to import Capstone for raw disassembly
        try:
            import capstone as cs
            
            # Initialize Capstone for ARM64
            md = cs.Cs(cs.CS_ARCH_ARM64, cs.CS_MODE_ARM)
            md.detail = False  # We don't need detailed analysis
            
            while current_ea < selection_end:
                # Get instruction size
                insn_size = idc.get_item_size(current_ea)
                if insn_size == 0:
                    insn_size = 4  # Default ARM64 instruction size
                
                # Read the bytes at this address
                insn_bytes = ida_bytes.get_bytes(current_ea, insn_size)
                if insn_bytes:
                    # Disassemble using Capstone with address 0 to get relative offsets
                    for insn in md.disasm(insn_bytes, 0, count=1):
                        # Format instruction - Capstone gives us pure disassembly with relative addressing
                        asm_line = "%s %s" % (insn.mnemonic.lower(), insn.op_str.lower())
                        disasm_lines.append(asm_line.strip())
                        break
                
                # Move to next instruction
                next_ea = idc.next_head(current_ea)
                if next_ea <= current_ea:
                    break
                current_ea = next_ea

            
        except ImportError:
            # If Capstone is not available, show a message
            ida_kernwin.msg("[ida_mask_plugin] Capstone not available. Please install capstone for raw disassembly.\n")
            ida_kernwin.warning("Capstone engine required for raw bytecode disassembly.\n\nInstall with: pip install capstone")
            return ""
        
        return "\n".join(disasm_lines)
    
    except Exception as e:
        ida_kernwin.msg("[ida_mask_plugin] Error getting selected disassembly: %s\n" % str(e))
        return ""


class IDAMaskUIHooks(idaapi.UI_Hooks):
    """UI hooks for contextual menu integration"""
    
    def __init__(self):
        idaapi.UI_Hooks.__init__(self)
    
    def finish_populating_widget_popup(self, widget, popup):
        """Add our menu items to the context menu"""
        # Only add to disassembly views
        widget_type = ida_kernwin.get_widget_type(widget)
        if widget_type == ida_kernwin.BWN_DISASM:
            try:
                # Add submenu items with proper submenu path like Keypatch does
                ida_kernwin.attach_action_to_popup(widget, popup, "ida_mask:search_context", "IDA Mask/")
                ida_kernwin.attach_action_to_popup(widget, popup, "-", "IDA Mask/")
                ida_kernwin.attach_action_to_popup(widget, popup, "ida_mask:create_context", "IDA Mask/")
            except:
                pass


class SearchContextActionHandler(ida_kernwin.action_handler_t):
    """Handler for contextual search action"""
    
    def activate(self, ctx):
        """Activate the search action"""
        pattern_input = ida_kernwin.ask_str("", 0, "Enter pattern:mask (hex:hex)")
        if pattern_input:
            search_pattern_mask(pattern_input)
        return 1

    def update(self, ctx):
        """Update action state"""
        return ida_kernwin.AST_ENABLE_ALWAYS


class CreateContextActionHandler(ida_kernwin.action_handler_t):
    """Handler for contextual create action"""
    
    def activate(self, ctx):
        """Activate the create action"""
        # Get selected disassembly
        selected_disasm = get_selected_disassembly()
        
        # Use selected disassembly as default or empty string
        default_text = selected_disasm if selected_disasm else ""
        
        # Show helpful message if we have pre-filled content
        title = "Enter assembly code"
        if selected_disasm:
            title += " (pre-filled from selection)"
        
        asm_input = ida_kernwin.ask_text(0, default_text, title)
        if asm_input:
            create_pattern_from_asm(asm_input)
        return 1

    def update(self, ctx):
        """Update action state"""
        return ida_kernwin.AST_ENABLE_ALWAYS


class PatternSearchResults(ida_kernwin.Choose):
    """Custom chooser to display pattern search results"""
    
    def __init__(self, title, results, pattern_hex, mask_hex):
        ida_kernwin.Choose.__init__(
            self,
            title,
            [
                ["Address", 10 | ida_kernwin.Choose.CHCOL_HEX],
                ["Segment", 10],
                ["Function", 20], 
                ["Bytes", 20],
                ["Offset", 10]
            ]
        )
        
        self.results = results
        self.pattern_hex = pattern_hex
        self.mask_hex = mask_hex
        self.items = []
        self.icon = -1
        self.populate_items()
    
    def populate_items(self):
        """Populate the chooser with result items"""
        self.items = []
        
        for addr in self.results:
            # Get segment name
            seg = ida_segment.getseg(addr)
            seg_name = ida_segment.get_segm_name(seg) if seg else "???"
            
            # Get function info
            func = ida_funcs.get_func(addr)
            if func:
                func_name = ida_funcs.get_func_name(func.start_ea)
                offset = addr - func.start_ea
                func_info = "%s+0x%X" % (func_name, offset)
            else:
                func_info = "-"
            
            # Get bytes at address
            pattern_len = len(self.pattern_hex) // 2
            actual_bytes = ida_bytes.get_bytes(addr, pattern_len)
            if actual_bytes:
                bytes_str = actual_bytes.hex().upper()
            else:
                bytes_str = "???"
            
            # Format offset from segment start
            if seg:
                seg_offset = "0x%X" % (addr - seg.start_ea)
            else:
                seg_offset = "-"
            
            self.items.append([
                "0x%08X" % addr,
                seg_name,
                func_info,
                bytes_str,
                seg_offset
            ])
    
    def get_size(self):
        """Return number of items"""
        return len(self.items)
    
    def get_line_attr(self, n):
        """Get line attributes"""
        return [0, 0]
    
    def get_line(self, n):
        """Get a line"""
        if n < len(self.items):
            return self.items[n]
        return []
    
    def OnSelectLine(self, n):
        """Handle line selection - jump to address"""
        if n < len(self.results):
            ida_kernwin.jumpto(self.results[n])
    
    def OnGetLine(self, n):
        """Get line for display"""
        return self.get_line(n)
    
    def OnGetSize(self):
        """Get size for display"""
        return self.get_size()


class PatternGenerationResults(idaapi.simplecustviewer_t):
    """Custom viewer to display pattern generation results"""
    
    def __init__(self):
        idaapi.simplecustviewer_t.__init__(self)
        self.title = "Pattern Generation Results"
    
    @staticmethod
    def show_results(instruction_results, combined_pattern, combined_mask):
        """Show pattern generation results in a custom viewer"""
        
        # Create viewer instance
        viewer = PatternGenerationResults()
        
        # Check if widget already exists
        if ida_kernwin.find_widget(viewer.title) is not None:
            ida_kernwin.close_widget(ida_kernwin.find_widget(viewer.title), 0)
        
        # Create the viewer
        if not viewer.Create(viewer.title):
            print("Unable to create pattern results viewer")
            return False
        
        # Clear any existing content
        viewer.ClearLines()
        
        # Add content
        viewer.AddLine("=" * 80)
        viewer.AddLine("PATTERN GENERATION RESULTS")
        viewer.AddLine("=" * 80)
        viewer.AddLine("")
        
        # Summary
        success_count = sum(1 for r in instruction_results if r['success'])
        total_count = len(instruction_results)
        viewer.AddLine("Summary: %d/%d instructions processed successfully" % (success_count, total_count))
        viewer.AddLine("")
        
        # Individual instruction results
        viewer.AddLine("INDIVIDUAL INSTRUCTIONS:")
        viewer.AddLine("-" * 80)
        
        for result in instruction_results:
            status = "SUCCESS" if result['success'] else "FAILED"
            viewer.AddLine("%2d. [%s] %s" % (result['index'], status, result['instruction']))
            
            if result['success']:
                viewer.AddLine("    Pattern: %s" % result['pattern'])
                viewer.AddLine("    Mask   : %s" % result['mask'])
                viewer.AddLine("    P:M    : %s:%s" % (result['pattern'], result['mask']))
            else:
                viewer.AddLine("    Error  : %s" % result['error'])
            viewer.AddLine("")
        
        # Combined result
        if success_count > 0:
            viewer.AddLine("=" * 80)
            viewer.AddLine("COMBINED RESULT:")
            viewer.AddLine("=" * 80)
            viewer.AddLine("")
            viewer.AddLine("Combined Pattern: %s" % combined_pattern)
            viewer.AddLine("Combined Mask   : %s" % combined_mask)
            viewer.AddLine("")
            viewer.AddLine("FINAL PATTERN:MASK:")
            viewer.AddLine("%s:%s" % (combined_pattern, combined_mask))
            viewer.AddLine("")
            viewer.AddLine("Pattern Length: %d bytes" % (len(combined_pattern) // 2))
            viewer.AddLine("")
        
        # Show the viewer
        viewer.Show()
        
        # Jump to top
        viewer.Jump(0, 0)
        
        return True


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
        
        # Install UI hooks for contextual menu
        self.ui_hooks = IDAMaskUIHooks()
        self.ui_hooks.hook()
        
        ida_kernwin.msg("[ida_mask_plugin] Plugin initialized successfully\n")
        return ida_idaapi.PLUGIN_KEEP

    def term(self):
        """Terminate the plugin"""
        ida_kernwin.msg("[ida_mask_plugin] Terminating plugin...\n")
        
        # Uninstall UI hooks
        if hasattr(self, 'ui_hooks'):
            self.ui_hooks.unhook()
        
        # Unregister actions
        self.unregister_actions()
        
        ida_kernwin.msg("[ida_mask_plugin] Plugin terminated\n")

    def run(self, arg):
        """Run the plugin - called when plugin is executed directly"""
        ida_kernwin.msg("[ida_mask_plugin] Plugin run() called with arg: %d\n" % arg)
        
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
        
        # Contextual menu actions
        search_context_action = ida_kernwin.action_desc_t(
            "ida_mask:search_context",
            "Search by pattern:mask",
            SearchContextActionHandler(),
            "",
            "Search binary for pattern with mask",
            -1
        )
        
        create_context_action = ida_kernwin.action_desc_t(
            "ida_mask:create_context",
            "Create pattern:mask",
            CreateContextActionHandler(),
            "",
            "Generate pattern:mask from assembly (with selection pre-fill)",
            -1
        )
        
        # Register actions
        ida_kernwin.register_action(search_action)
        ida_kernwin.register_action(create_action)
        ida_kernwin.register_action(search_context_action)
        ida_kernwin.register_action(create_context_action)
        
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
        ida_kernwin.unregister_action("ida_mask:search_context")
        ida_kernwin.unregister_action("ida_mask:create_context")

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
    Display search results in both console and a results view
    
    Args:
        results: List of addresses where pattern was found
        pattern_hex: Original pattern hex string
        mask_hex: Original mask hex string
    """
    # Display in console
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
    
    # Show results in a dedicated chooser window
    if results:
        title = "Pattern Search Results - %s:%s" % (pattern_hex[:16], mask_hex[:16])
        if len(pattern_hex) > 16:
            title += "..."
        
        chooser = PatternSearchResults(title, results, pattern_hex, mask_hex)
        chooser.Show()


def create_pattern_from_asm(asm_text):
    """
    Generate pattern:mask from assembly code
    
    Args:
        asm_text: Assembly code as string
    """
    ida_kernwin.msg("[ida_mask_plugin] create_pattern_from_asm called with %d bytes\n" % len(asm_text))

    # Try to import the Python wrapper for the Rust library
    try:
        import arm64_mask_gen_py
    except Exception as e:
        ida_kernwin.warning("arm64_mask_gen_py not available: %s" % e)
        ida_kernwin.msg("Assembly input (mock):\n%s\n" % asm_text)
        ida_kernwin.info("Pattern generation from assembly not available; build and install the Python extension first.")
        return False

    # Split assembly text into individual instructions
    instructions = []
    for line in asm_text.strip().split('\n'):
        line = line.strip()
        if line and not line.startswith(';') and not line.startswith('#'):
            instructions.append(line)
    
    if not instructions:
        ida_kernwin.warning("No valid instructions found in input")
        return False
    
    ida_kernwin.msg("[ida_mask_plugin] Processing %d instructions...\n" % len(instructions))
    
    # Process each instruction individually
    instruction_results = []
    successful_patterns = []
    successful_masks = []
    failed_instructions = []
    
    for i, instruction in enumerate(instructions, 1):
        ida_kernwin.msg("[ida_mask_plugin] Processing instruction %d: %s\n" % (i, instruction))
        
        result = {
            'index': i,
            'instruction': instruction,
            'success': False,
            'pattern': '',
            'mask': '',
            'error': ''
        }
        
        try:
            # Generate pattern for single instruction
            pat, msk = arm64_mask_gen_py.make_r2_mask(instruction)
            
            # Validate the result
            if pat and msk and len(pat) == len(msk):
                result['success'] = True
                result['pattern'] = pat
                result['mask'] = msk
                
                successful_patterns.append(pat)
                successful_masks.append(msk)
                ida_kernwin.msg("[ida_mask_plugin]   ✓ Pattern: %s\n" % pat)
                ida_kernwin.msg("[ida_mask_plugin]   ✓ Mask   : %s\n" % msk)
            else:
                result['error'] = "Invalid pattern/mask generated"
                failed_instructions.append((i, instruction, "Invalid pattern/mask generated"))
                ida_kernwin.msg("[ida_mask_plugin]   ✗ Failed: Invalid pattern/mask\n")
                
        except Exception as e:
            result['error'] = str(e)
            failed_instructions.append((i, instruction, str(e)))
            ida_kernwin.msg("[ida_mask_plugin]   ✗ Failed: %s\n" % str(e))
        
        instruction_results.append(result)
    
    # Report results
    ida_kernwin.msg("\n" + "="*60 + "\n")
    ida_kernwin.msg("PATTERN GENERATION RESULTS\n")
    ida_kernwin.msg("="*60 + "\n")
    ida_kernwin.msg("Successful: %d/%d instructions\n" % (len(successful_patterns), len(instructions)))
    
    if failed_instructions:
        ida_kernwin.msg("Failed instructions:\n")
        for idx, instr, error in failed_instructions:
            ida_kernwin.msg("  %d. %s - %s\n" % (idx, instr, error))
        ida_kernwin.msg("\n")
    
    if not successful_patterns:
        ida_kernwin.warning("No instructions could be processed successfully")
        return False
    
    # Combine all successful patterns into a general pattern:mask
    combined_pattern = ''.join(successful_patterns)
    combined_mask = ''.join(successful_masks)
    
    ida_kernwin.msg("COMBINED PATTERN:MASK\n")
    ida_kernwin.msg("-"*60 + "\n")
    ida_kernwin.msg("Pattern: %s\n" % combined_pattern)
    ida_kernwin.msg("Mask   : %s\n" % combined_mask)
    ida_kernwin.msg("Combined: %s:%s\n" % (combined_pattern, combined_mask))
    ida_kernwin.msg("Length : %d bytes\n" % (len(combined_pattern) // 2))
    ida_kernwin.msg("="*60 + "\n")
    
    # Show success dialog with combined result
    result_msg = "Pattern generation completed!\n\n"
    result_msg += "Successfully processed: %d/%d instructions\n\n" % (len(successful_patterns), len(instructions))
    result_msg += "Combined Pattern:Mask:\n%s:%s\n\n" % (combined_pattern, combined_mask)
    result_msg += "Pattern length: %d bytes\n\n" % (len(combined_pattern) // 2)
    
    if failed_instructions:
        result_msg += "Note: %d instruction(s) failed - see Output window for details." % len(failed_instructions)
    else:
        result_msg += "All instructions processed successfully!"
    
    ida_kernwin.info(result_msg)
    
    # Show results in a text viewer window
    PatternGenerationResults.show_results(instruction_results, combined_pattern, combined_mask)
    
    return True


def PLUGIN_ENTRY():
    """Plugin entry point"""
    return IDAMaskPlugin()
