# Kaspersky Lab Flash Debugger Plugin
#
# Copyright (C) 2018 Kaspersky Lab
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import idaapi
import idc
from ida_kernwin import *
from ida_idd import *
from ida_bytes import *
from ida_netnode import *
from ida_segment import *
from ida_search import *
from ida_name import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
import time
import cPickle

klfdb = None

class DebugListDialog(QDialog):
	def __init__(self, as3dump, selected = [], appended = [], parent = None):
		super(DebugListDialog, self).__init__(parent)

		layout = QVBoxLayout(self)

		self.selected = selected
		self.appended = appended

		self.table = QListWidget(self)

		for i in range(len(as3dump)):
			item = QListWidgetItem(as3dump[i]["name"])
			item.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)

			if (i in selected):
				item.setCheckState(Qt.Checked)
			else:
				item.setCheckState(Qt.Unchecked)

			self.table.addItem(item)

		for i in range(len(appended)):
			item = QListWidgetItem(appended[i])
			item.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)

			if (i+len(as3dump) in selected):
				item.setCheckState(Qt.Checked)
			else:
				item.setCheckState(Qt.Unchecked)

			self.table.addItem(item)

		self.table.itemClicked.connect(self.handle_item_click)

		layout.addWidget(self.table)

		layout2 = QHBoxLayout()
		self.check_button = QPushButton("Check all")
		self.uncheck_button = QPushButton("Uncheck all")
		self.check_button.clicked.connect(self.check_all)
		self.uncheck_button.clicked.connect(self.uncheck_all)
		layout2.addWidget(self.check_button)
		layout2.addWidget(self.uncheck_button)
		layout.addLayout(layout2)

		self.add_button = QPushButton("Break on ...")
		self.add_button.clicked.connect(self.add_text)
		layout.addWidget(self.add_button)

		self.buttons = QDialogButtonBox(
			QDialogButtonBox.Ok | QDialogButtonBox.Cancel,
			Qt.Horizontal, self)
		layout.addWidget(self.buttons)

		self.buttons.accepted.connect(self.accept)
		self.buttons.rejected.connect(self.reject)

	def handle_item_click(self, item):

		index = self.table.indexFromItem(item).row()

		if (item.checkState() == Qt.Checked):
			if (index not in self.selected):
				self.selected.append(index)
		else:
			self.selected = [x for x in self.selected if x != index]

	def add_text(self):
		text, ok = QInputDialog.getText(self, 'Break on ...', 'Part of a string or full name:')

		if (ok):
			
			for i in range(self.table.count()):

				if (self.table.item(i).text() == text):
					self.table.item(i).setCheckState(Qt.Checked)

					if (i not in self.selected):
						self.selected.append(i)

					self.table.scrollToItem(self.table.item(i), 0)
					return

			if (text not in self.appended):

				item = QListWidgetItem(text)
				item.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
				item.setCheckState(Qt.Checked)
				self.table.addItem(item)

				index = self.table.indexFromItem(item).row()
				self.appended.append(text)
				self.selected.append(index)
	
				self.table.scrollToItem(item, 0)

	def check_all(self):

		for i in range(self.table.count()):
			self.table.item(i).setCheckState(Qt.Checked)

		self.selected = [x for x in range(self.table.count())]

	def uncheck_all(self):

		for i in range(self.table.count()):
			self.table.item(i).setCheckState(Qt.Unchecked)

		self.selected = []

	@staticmethod
	def get_selected(as3dump, selected = [], appended = [], parent = None):

		old_selected = selected[:]
		old_appended = appended[:]

		dialog = DebugListDialog(as3dump, selected, appended, parent)
		result = dialog.exec_()
		new_selected = dialog.selected
		new_appended = dialog.appended
		dialog.close()

		if (result == QDialog.Accepted):
			return new_selected, new_appended
		else:
			return old_selected, old_appended

class IgnoreListDialog(QDialog):
	def __init__(self, selected = [], appended = [], ignore = False, parent = None):
		super(IgnoreListDialog, self).__init__(parent)

		layout = QVBoxLayout(self)

		self.selected = selected
		self.appended = appended
		self.ignore = ignore

		self.table = QListWidget(self)

		for i in range(len(appended)):
			item = QListWidgetItem(appended[i])
			item.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)

			if (i in selected):
				item.setCheckState(Qt.Checked)
			else:
				item.setCheckState(Qt.Unchecked)

			self.table.addItem(item)

		self.table.itemClicked.connect(self.handle_item_click)

		layout.addWidget(self.table)

		layout2 = QHBoxLayout()
		self.check_button = QPushButton("Check all")
		self.uncheck_button = QPushButton("Uncheck all")
		self.check_button.clicked.connect(self.check_all)
		self.uncheck_button.clicked.connect(self.uncheck_all)
		layout2.addWidget(self.check_button)
		layout2.addWidget(self.uncheck_button)
		layout.addLayout(layout2)

		self.add_button = QPushButton("Ignore ...")
		self.add_button.clicked.connect(self.add_text)
		layout.addWidget(self.add_button)

		layout3 = QHBoxLayout()
		layout3.setAlignment(Qt.AlignCenter)
		self.checkbox = QCheckBox("Ignore all")
		self.checkbox.clicked.connect(self.ignore_all)
		layout3.addWidget(self.checkbox)
		layout.addLayout(layout3)

		self.buttons = QDialogButtonBox(
			QDialogButtonBox.Ok | QDialogButtonBox.Cancel,
			Qt.Horizontal, self)
		layout.addWidget(self.buttons)

		self.buttons.accepted.connect(self.accept)
		self.buttons.rejected.connect(self.reject)

	def handle_item_click(self, item):

		index = self.table.indexFromItem(item).row()

		if (item.checkState() == Qt.Checked):
			if (index not in self.selected):
				self.selected.append(index)

		else:
			self.selected = [x for x in self.selected if x != index]

	def add_text(self):
		text, ok = QInputDialog.getText(self, 'Ignore ...', 'Full name:')
		
		if (ok and text not in self.appended):

			item = QListWidgetItem(text)
			item.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
			item.setCheckState(Qt.Checked)
			self.table.addItem(item)

			index = self.table.indexFromItem(item).row()
			self.appended.append(text)
			self.selected.append(index)

			self.table.scrollToItem(item, 0)

	def check_all(self):

		for i in range(self.table.count()):
			self.table.item(i).setCheckState(Qt.Checked)

		self.selected = [x for x in range(self.table.count())]

	def uncheck_all(self):

		for i in range(self.table.count()):
			self.table.item(i).setCheckState(Qt.Unchecked)

		self.selected = []

	def ignore_all(self, checked):

		for i in range(self.table.count()):
			self.table.item(i).setFlags(self.table.item(i).flags() ^ (Qt.ItemIsSelectable | Qt.ItemIsEnabled))

		self.check_button.setEnabled(not self.check_button.isEnabled())
		self.uncheck_button.setEnabled(not self.uncheck_button.isEnabled())
		self.add_button.setEnabled(not self.add_button.isEnabled())

		self.ignore = not self.ignore

	@staticmethod
	def get_selected(selected = [], appended = [], ignore_all = False, parent = None):

		old_selected = selected[:]
		old_appended = appended[:]

		dialog = IgnoreListDialog(selected, appended, ignore_all, parent)
		result = dialog.exec_()
		new_selected = dialog.selected
		new_appended = dialog.appended
		dialog.close()

		if (result == QDialog.Accepted):
			return new_selected, new_appended, ignore_all
		else:
			return old_selected, old_appended, ignore_all

class Klfdb:

	def __init__(self):

		self.signatures = {
			"BaseExecMgr::verifyNative": [ 
				"8B 41 08 80 78 38 00 8B 44 24 04 74 10 8B 50 28", # For Stand Alone (SA) and Internet Explorer (OCX) - since 11.x.x.x
				"55 8B EC 8B 41 08 80 78 38 00 8B 45 08 74 0F 8B"  # For Stand Alone (SA) and Internet Explorer (OCX) - since 30.0.0.113
			],
			"BaseExecMgr::setJit": [
				"8B 4C 24 08 56 8B 74 24 08 8B 46 30 25 FF FF 7F", # For Stand Alone (SA) and Internet Explorer (OCX) - since 11.x.x.x
				"56 8B 74 24 08 F6 46 33 01 74 10",				   # For Stand Alone (SA) and Internet Explorer (OCX) - 29.0.0.113, 29.0.0.171
				"55 8B EC 56 8B 75 08 F7 46 30 00 00 00 01 74 10"  # For Stand Alone (SA) and Internet Explorer (OCX) - since 30.0.0.113
			],
			"BaseExecMgr::setInterp": [
				"33 C0 38 44 24 0C 53 55 0F 95 C0 56 8B 74 24 10", # For Stand Alone (SA) and Internet Explorer (OCX) - since 11.x.x.x
				"51 53 55 56 8B 74 24 14 F6 46 33 01 57 89 4C 24", # For Stand Alone (SA) and Internet Explorer (OCX) - 29.0.0.113, 29.0.0.171
				"55 8B EC 51 53 56 8B 75 08 57 89 4D FC F7 46 30"  # For Stand Alone (SA) and Internet Explorer (OCX) - since 30.0.0.113
			],
			"MethodInfo::getMethodName": [
				"8B 41 10 A8 01 74 13 83 E0 FE 74 0C 8B 40 0C 52", # For Stand Alone (SA) and Internet Explorer (OCX) - since 11.x.x.x
				"F6 41 10 01 56 8B F2 75 0B 8B 51 10 56"		   # For Stand Alone (SA) and Internet Explorer (OCX) - since 30.0.0.113
			],
			"BaseExecMgr::verifyJit": [
				"81 EC 6C 01 00 00 53 8B 9C 24 78 01 00 00 55 8B", # For Stand Alone (SA) and Internet Explorer (OCX) - since 12.x.x.x
				"8B 44 24 14 81 EC 78 01 00 00 53 8B 9C 24 84 01", # For Stand Alone (SA) and Internet Explorer (OCX) - 11.x.x.x
				"55 8B EC 81 EC 6C 01 00 00 53 8B 5D 08 56 8B 75"  # For Stand Alone (SA) and Internet Explorer (OCX) - since 30.0.0.113
			],
			"CodegenLIR::writePrologue": [
				"83 EC 20 8B 44 24 24 53 8B 5C 24 2C 55 56 8B F1", # For Stand Alone (SA) and Internet Explorer (OCX) - since 11.x.x.x
				"55 8B EC 83 EC 20 8B 45 08 53 8B 5D 10 56 8B F1", # For Stand Alone (SA) and Internet Explorer (OCX) - since 30.0.0.113
			],
			"Verifier::hasReachableExceptions": [
				"8A 41 39 C3 CC CC CC CC CC CC CC CC CC CC CC CC"  # For Stand Alone (SA) and Internet Explorer (OCX) - since 11.x.x.x
			],
		}

		self.save_eip = True
		self.jit_max_size = 0x10000
		self.max_hit_count = 100
		self.timeout_seconds = 60

		self.base = 0
		self.addr = {}
		self.traced = []
		self.get_method_name_func = None
		self.debug_if_equals = []
		self.debug_if_contains = []
		self.ignore = []

		self.data_loaded = False
		self.as3dump = []
		self.debug_selected = []
		self.debug_appended = []
		self.ignore_selected = []
		self.ignore_appended = []
		self.ignore_all = False

	def store_data(self):

		dump = {}
		dump["as3dump"] = self.as3dump
		dump["debug_selected"] = self.debug_selected
		dump["debug_appended"] = self.debug_appended
		dump["ignore_selected"] = self.ignore_selected
		dump["ignore_appended"] = self.ignore_appended
		dump["ignore_all"] = self.ignore_all

		data = cPickle.dumps(dump)

		node = netnode("$ klfdb", 0, True)
		node.setblob(data, 0, stag)

	def load_data(self):

		try:
			node = netnode("$ klfdb", 0, True)
			data = node.getblob(0, stag)
	
			if (data is not None):
	
				ret = ask_yn(-1, 'This .idb file contains stored data of "Klfdb" plugin. Would you like to load it?\n'
								 'Do not load this data if .idb file come from untrusted source - it might be not safe')

				if (ret == 1):

					dump = cPickle.loads(data)
			
					self.as3dump = dump["as3dump"]
					self.debug_selected = dump["debug_selected"]
					self.debug_appended = dump["debug_appended"]
					self.ignore_selected = dump["ignore_selected"]
					self.ignore_appended = dump["ignore_appended"]
					self.ignore_all = dump["ignore_all"]

		except Exception as e:
			return

	def get_trace_whitelist(self):

		self.debug_if_equals = []
		self.debug_if_contains = []

		for i in self.debug_selected:

			if (i < len(self.as3dump)):
				self.debug_if_equals.append(self.as3dump[i]["name"])
			else:
				self.debug_if_contains.append(str(self.debug_appended[i - len(self.as3dump)]))

	def get_trace_blacklist(self):

		self.ignore = []

		for i in self.ignore_selected:
			self.ignore.append(str(self.ignore_appended[i]))

	def resolve_functions(self):

		self.addr = {
			"verifyNative": idc.get_name_ea_simple("BaseExecMgr::verifyNative"), 
			"setJit": idc.get_name_ea_simple("BaseExecMgr::setJit"), 
			"setInterp": idc.get_name_ea_simple("BaseExecMgr::setInterp"), 
			"setInterpRet": prev_head(
				idc.find_func_end(idc.get_name_ea_simple("BaseExecMgr::setInterp")), 
				idc.get_name_ea_simple("BaseExecMgr::setInterp")), 
			"getMethodName": idc.get_name_ea_simple("MethodInfo::getMethodName"), 
			"verifyJit": idc.get_name_ea_simple("BaseExecMgr::verifyJit"), 
			"writePrologue": idc.get_name_ea_simple("CodegenLIR::writePrologue"),
			"hasReachableExceptionsRet": prev_head(
				idc.find_func_end(idc.get_name_ea_simple("Verifier::hasReachableExceptions")), 
				idc.get_name_ea_simple("Verifier::hasReachableExceptions"))
		}

	def check_resolved_functions(self):
	
		if (any(x for x in self.addr if self.addr[x] == idc.BADADDR)):
			return False

		return True

	def find_functions(self):

		code_start = get_segm_by_name(".text").start_ea
		code_end = get_segm_by_name(".text").end_ea
		
		for name in self.signatures:
		
			found = False
			for sig in self.signatures[name]:
				
				pos = find_binary(code_start, code_end, sig, 16, SEARCH_DOWN)
		
				if (pos != idc.BADADDR):
					set_name(pos, name, SN_NOCHECK | SN_NOWARN | SN_FORCE)
					found = True
					break
		
			if (not found):
				print('Failed to find signature of "%s"' % name)
				return False
		
		return True

	def get_functions(self):

		# Try to get instrumented functions by their name
		self.resolve_functions()

		if (self.check_resolved_functions()):
			return True

		# If they are not named in .idb try to find them by their signature
		if (not self.find_functions()):
			return False

		self.resolve_functions()

		return True

	def get_base(self):
		return get_segm_by_name(".text").start_ea & 0xFFFF0000
	
	def set_breakpoints(self):
	
		idc.add_bpt(self.addr["verifyNative"])
		idc.add_bpt(self.addr["setJit"])
		idc.add_bpt(self.addr["setInterp"])
		idc.add_bpt(self.addr["setInterpRet"])
		idc.add_bpt(self.addr["writePrologue"])
		idc.add_bpt(self.addr["hasReachableExceptionsRet"])

	def cleanup_breakpoints(self):

		if (self.addr == {}):
			return False

		idc.del_bpt(self.addr["verifyNative"])
		idc.del_bpt(self.addr["setJit"])
		idc.del_bpt(self.addr["setInterp"])
		idc.del_bpt(self.addr["setInterpRet"])
		idc.del_bpt(self.addr["writePrologue"])
		idc.del_bpt(self.addr["hasReachableExceptionsRet"])

		# We want to delete all breakpoints that were set by plugin to trace execution 

		for function in self.traced:
			# Functions listed here can be either present in ".text" segment or in memory regions that are no longer present
			# Try to delete them twice
			idc.del_bpt(function["ea"])
			idc.del_bpt(function["ea"] - self.base + self.get_base())

		self.traced = []

		return True

	def init(self):

		if (idc.get_process_state() == idc.DSTATE_NOTASK):
			return False

		self.get_trace_whitelist()
		self.get_trace_blacklist()

		if (not self.get_functions()):
			return False
	
		# If base address changed - it means debugger was re-launched
		if (self.base != self.get_base()):
			self.cleanup_breakpoints()
			self.base = self.get_base()

		self.set_breakpoints()
		
		# MethodInfo::getMethodName@<eax>(avmplus::MethodInfo *this@<ecx>, bool includeAllNamespaces@<dl>)
		self.get_method_name_func = Appcall.proto(self.addr["getMethodName"], 
												  "void* __fastcall func(void*, bool);")
		return True

	def wait_event(self):

		timeout = time.time() + self.timeout_seconds

		try:
			idc.resume_process()
		
			val = 0
			while(val != idc.BREAKPOINT and val != idc.EXCEPTION):
				val = idc.wait_for_next_event(idc.WFNE_ANY, 5)

				if (val == idc.LIB_LOADED):
					# New library was loaded - maybe our module was rebased?
					if (self.base != self.get_base()):
						print("Flash module is rebased.")

						if (not self.init()):
							print("Re-initialize after rebase is failed.")
							return False

				if (time.time() > timeout):

					ret = ask_yn(-1, 'Timeout %d seconds. Would you like to continue execution?' % self.timeout_seconds)

					if (ret == 1):
						timeout = time.time() + self.timeout_seconds
					else:
						return False

		except Exception as e:
			return

		return True

	def get_method_name(self, esp):

		stringp = self.get_method_name_func(idc.get_wide_dword(esp + 4), 0)
		address = idc.get_wide_dword(stringp + 0x8)
		return idc.get_strlit_contents(address, -1, idc.STRTYPE_C)

	def rename_addr(self, addr, name):

		if (not has_user_name(get_full_flags(addr)) and name is not None):
			set_name(addr, name, SN_NOCHECK | SN_NOWARN)

	def get_func_end(self, start):

		if (idc.add_func(start)):
			return idc.find_func_end(start)

		ea = start
		while (idc.get_wide_byte(ea) != 0xCC):
			idc.create_insn(ea)
			ea += idc.get_item_size(ea)

			if (ea - start > self.jit_max_size):
				return 0

		return ea

	def get_stack_vars(self, start, end):

		stackvars = {}
	
		ea = start
		while (ea < end):
	
			if ("ebp" in idc.print_operand(ea, 0) and idc.get_operand_type(ea, 1) == idc.o_imm):
	
				op0 = idc.get_operand_value(ea, 0)
				op1 = idc.get_operand_value(ea, 1)
	
				if (op0 in stackvars):
					stackvars[op0]["values"].append(op1)
				else:
					stackvars[op0] = {"values": [], "hits": 0}
	
			ea += idc.get_item_size(ea)

		return stackvars

	def get_save_eip(self, method, stackvars):
	
		for offset in method["instructions"]:
			for var in stackvars:
				if (offset in stackvars[var]["values"]):
					stackvars[var]["hits"] += 1
	
		return sorted(stackvars.iteritems(), key=lambda (k,v): v['hits'], reverse=True)[0][0]

	def set_jit_info(self, method_id, start):

		end = self.get_func_end(start)

		if (end < start or end - start > self.jit_max_size):
			return

		method = next((x for x in self.as3dump if x["id"] == method_id), None)

		if (method is None):
			return

		stackvars = self.get_stack_vars(start, end)
		save_eip = self.get_save_eip(method, stackvars)

		ea = start
		while (ea < end):
	
			if ("ebp" in idc.print_operand(ea, 0) and idc.get_operand_type(ea, 1) == idc.o_imm):
	
				op0 = idc.get_operand_value(ea, 0)
				op1 = idc.get_operand_value(ea, 1)
	
				if (op0 == save_eip):
					idc.set_cmt(ea, method["instructions"][op1], 0)
		
			ea += idc.get_item_size(ea)

	def get_native_function(self):

		ecx = idc.get_reg_value("ECX")
		esp = idc.get_reg_value("ESP")

		method_name = self.get_method_name(esp)
		
		if (idc.get_wide_byte(idc.get_wide_dword(ecx + 8) + 0x38) != 0):
			function = idc.get_wide_dword(idc.get_wide_dword(esp + 4) + 0x28)
		else:
			function = idc.get_wide_dword(idc.get_wide_dword(esp + 4) + 0x24)
		
		print("Resolved native function: 0x%x - %s" % (function, method_name))

		if ((method_name not in self.ignore and not self.ignore_all) or
			(method_name in self.debug_if_equals) or 
			(any(x for x in self.debug_if_contains if method_name is not None and x in method_name))):
			self.traced.append({"name": method_name, "ea": function, "type": "native", "hit": 0})
			idc.add_bpt(function)

	def get_jit_function(self):

		esp = idc.get_reg_value("ESP")

		method_name = self.get_method_name(esp)
		function = idc.get_wide_dword(esp + 8)

		method_id = idc.get_wide_dword(idc.get_wide_dword(esp + 4) + 0x20)
		abc_info_pos = idc.get_wide_dword(idc.get_wide_dword(esp + 4) + 0x1C)
		method_info = get_qword(abc_info_pos) + get_qword(abc_info_pos + 8)
		
		if (self.as3dump != []):

			method = next((x for x in self.as3dump if x["id"] == method_id), None)

			if (method is not None and method["info"] == method_info):
				method_name = method["name"]
				self.set_jit_info(method_id, function)

		print("Resolved jit function: 0x%x - %s" % (function, method_name))

		self.rename_addr(function, method_name)

		if ((method_name not in self.ignore and not self.ignore_all) or
			(method_name in self.debug_if_equals) or 
			(any(x for x in self.debug_if_contains if method_name is not None and x in method_name))):
			self.traced.append({"name": method_name, "ea": function, "type": "jit", "hit": 0})
			idc.add_bpt(function)

	def get_interpreted_function(self, eip):

		if (eip == self.addr["setInterp"]):
			
			esp = idc.get_reg_value("ESP")
			self.method_name = self.get_method_name(esp)
		
			self.is_interpreted_state = True
		
		elif (eip == self.addr["setInterpRet"] and self.is_interpreted_state):

			function = idc.get_reg_value("EAX")
			
			print("Resolved interpreted function: 0x%x - %s" % (function, self.method_name))
			
			if ((self.method_name not in self.ignore and not self.ignore_all) or
				(self.method_name in self.debug_if_equals) or 
				(any(x for x in self.debug_if_contains if self.method_name is not None and x in self.method_name))):
				self.traced.append({"name": self.method_name, "ea": function, "type": "interp", "hit": 0})
				idc.add_bpt(function)
		
			self.is_interpreted_state = False	

	def force_save_eip_generation(self, eip):

		if (eip == self.addr["writePrologue"] and self.save_eip):

			self.is_write_prologue_state = True

		elif (eip == self.addr["hasReachableExceptionsRet"] and self.save_eip and self.is_write_prologue_state):

			idc.set_reg_value(1, "EAX")
			self.is_write_prologue_state = False

	def stop_execution(self, eip, break_on_next):

		function = next((x for x in self.traced if x["ea"] == eip), None)
		
		if (function is not None):

			function["hit"] += 1
		
			print("[*] Executing %s" % function["name"])
		
			if (function["hit"] == self.max_hit_count):

				ret = ask_yn(-1, 'Function "%s" was hit %d times. Would you like to exclude it from trace list?' % (function["name"], self.max_hit_count))

				if (ret == 1):

					if (function["name"]):
						self.ignore_appended.append(function["name"])

					idc.del_bpt(function["ea"])

			# Check if we want to debug it

			if (break_on_next):
				return True

			if (function["name"] is not None):

				if (function["name"] in self.debug_if_equals):
					return True
	
				if (any(x for x in self.debug_if_contains if x in function["name"])):
					return True

			return False
		
		return True

	def handler(self, break_on_next = False):

		if (not self.init()):
			return False

		timeout = time.time() + self.timeout_seconds

		while(self.wait_event()):
		
			eip = idc.get_reg_value("EIP")
			
			if (eip == self.addr["verifyNative"]):
				self.get_native_function()
			
			elif (eip == self.addr["setJit"]):
				self.get_jit_function()
		
			elif (eip == self.addr["setInterp"] or eip == self.addr["setInterpRet"]):
				self.get_interpreted_function(eip)

			elif (eip == self.addr["writePrologue"] or eip == self.addr["hasReachableExceptionsRet"]):
				self.force_save_eip_generation(eip)

			elif (self.stop_execution(eip, break_on_next)):
				break

			if (time.time() > timeout):

				ret = ask_yn(-1, 'Timeout %d seconds. Would you like to continue execution?' % self.timeout_seconds)

				if (ret == 1):
					timeout = time.time() + self.timeout_seconds
				else:
					return False

		return True

	def load_as3_dump(self):

		path = ask_file(0, "*.map", "Load listing")

		if (path is None):
			return False

		file = open(path, "rb")
		data = file.read()
		file.close()

		self.as3dump = cPickle.loads(data)

		self.debug_selected = []
		self.debug_appended = []
		self.ignore_selected = []
		self.ignore_appended = []
		self.ignore_all = False

		self.store_data()

		return True

	def clear_as3_dump(self):

		ret = ask_yn(-1, "This operation will remove map data. Are you sure?")

		if (ret == 1):

			self.as3dump = []
			self.debug_selected = []
			self.debug_appended = []
			self.ignore_selected = []
			self.ignore_appended = []
			self.ignore_all = False
	
			self.store_data()

			return True

		return False

	def debug_list(self):

		if (self.as3dump == []):
			self.load_as3_dump()

		app = QWidget()

		self.debug_selected, self.debug_appended = DebugListDialog.get_selected(
			self.as3dump, self.debug_selected, self.debug_appended)

		if (self.debug_selected == []):
			return False
		else:
			self.store_data()
			return True

	def ignore_list(self):

		app = QWidget()

		self.ignore_selected, self.ignore_appended, self.ignore_all = IgnoreListDialog.get_selected(
			self.ignore_selected, self.ignore_appended, self.ignore_all)

		if (self.ignore_selected == []):
			return False
		else:
			self.store_data()
			return True

	class KlfdbHundler(action_handler_t):

		def __init__(self):
			action_handler_t.__init__(self)

		def activate(self, ctx):
			global klfdb
	
			# Try to load stored data right before plugin usage
			if (not klfdb.data_loaded):
				klfdb.load_data()
				klfdb.data_loaded = True

			if (ctx.action == 'klfdb:run'):
				if (klfdb.debug_selected == []):
					if (not klfdb.debug_list()):
						return False
	
				return klfdb.handler()
	
			elif (ctx.action == 'klfdb:runnext'):
				return klfdb.handler(break_on_next = True)
	
			elif (ctx.action == 'klfdb:delbpts'):
				return klfdb.cleanup_breakpoints()

			elif (ctx.action == 'klfdb:setbpts'):
				return klfdb.debug_list()
	
			elif (ctx.action == 'klfdb:ignore'):
				return klfdb.ignore_list()

			elif (ctx.action == 'klfdb:loadmap'):
				return klfdb.load_as3_dump()

			elif (ctx.action == 'klfdb:delmap'):
				return klfdb.clear_as3_dump()

			else:
				return False

		def update(self, ctx):

			if (idc.get_inf_attr(idc.INF_PROCNAME) != "metapc"):
				return AST_DISABLE

			if (ctx.action == 'klfdb:run'):
				if (idc.get_process_state() == idc.DSTATE_SUSP):
					return AST_ENABLE
				return AST_DISABLE
	
			elif (ctx.action == 'klfdb:runnext'):
				if (idc.get_process_state() == idc.DSTATE_SUSP):
					return AST_ENABLE
				return AST_DISABLE
	
			elif (ctx.action == 'klfdb:delbpts'):
				return AST_ENABLE

			elif (ctx.action == 'klfdb:setbpts'):
				return AST_ENABLE
	
			elif (ctx.action == 'klfdb:ignore'):
				return AST_ENABLE

			elif (ctx.action == 'klfdb:loadmap'):
				return AST_ENABLE

			elif (ctx.action == 'klfdb:delmap'):
				return AST_ENABLE

			return AST_DISABLE

	def create_action_menu(self, handler, name, menupath, label, shortcut = None):
	
		if (shortcut):
			register_action(action_desc_t(name, label, handler, shortcut))
		else:
			register_action(action_desc_t(name, label, handler))

		attach_action_to_menu(menupath, name, SETMENU_APP)

	def add_menu_items(self):

		handler = self.KlfdbHundler()
		path = 'Edit/Klfdb/'
		self.create_action_menu(handler, 'klfdb:run',	 path, 'Run', 'Ctrl+Shift+F9')
		self.create_action_menu(handler, 'klfdb:runnext', path, 'Run to next function', 'Ctrl+Alt+F9')
		self.create_action_menu(handler, 'klfdb:delbpts', path, 'Remove trace breakpoints')
		self.create_action_menu(handler, 'klfdb:setbpts', path, 'Set breakpoints on ...')
		self.create_action_menu(handler, 'klfdb:ignore',  path, 'Ignore traced function ...')
		self.create_action_menu(handler, 'klfdb:loadmap', path, 'Load new map file')
		self.create_action_menu(handler, 'klfdb:delmap',  path, 'Remove map data')

class klfdb_plugin_t(idaapi.plugin_t):
	flags = idaapi.PLUGIN_UNL
	comment = "Kaspersky Lab Flash Debugger Plugin"

	help = comment
	wanted_name = "Klfdb"
	wanted_hotkey = ""

	initialized = False

	def init(self):

		global klfdb

		if (not self.initialized):
			klfdb = Klfdb()
			klfdb.add_menu_items()
			initialized = True

		return idaapi.PLUGIN_OK

	def run(self, arg):
		print('Klfdb initialized. Go to "Edit\\Klfdb\\..."')
		return

	def term(self):
		return

def PLUGIN_ENTRY():
	return klfdb_plugin_t()
