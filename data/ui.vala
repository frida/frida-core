/* generated file, do not modify */
namespace Zed.Data.Ui {
	public static const string AGENT_SESSION_XML = "<?xml version=\"1.0\" ?>" +
		"<interface><!-- interface-naming-policy project-wide -->" +
"" +
"<object class=\"GtkVBox\" id=\"root_vbox\">" +
			"<property name=\"visible\">True</property>" +
			"<property name=\"orientation\">vertical</property>" +
			"<child>" +
				"<object class=\"GtkFrame\" id=\"control_frame\">" +
					"<property name=\"visible\">True</property>" +
					"<property name=\"label_xalign\">0</property>" +
					"<property name=\"shadow_type\">none</property>" +
					"<child>" +
						"<object class=\"GtkTable\" id=\"control_table\">" +
							"<property name=\"visible\">True</property>" +
							"<property name=\"n_columns\">3</property>" +
							"<child>" +
								"<object class=\"GtkAlignment\" id=\"process_info_alignment\">" +
									"<property name=\"visible\">True</property>" +
									"<property name=\"xalign\">0</property>" +
									"<property name=\"xscale\">0</property>" +
									"<property name=\"yscale\">0</property>" +
									"<property name=\"left_padding\">50</property>" +
									"<property name=\"right_padding\">50</property>" +
									"<child>" +
										"<placeholder/>" +
									"</child>" +
								"</object>" +
								"<packing>" +
									"<property name=\"y_options\">GTK_FILL</property>" +
								"</packing>" +
							"</child>" +
							"<child>" +
								"<object class=\"GtkAlignment\" id=\"go_button_alignment\">" +
									"<property name=\"visible\">True</property>" +
									"<property name=\"top_padding\">5</property>" +
									"<property name=\"bottom_padding\">5</property>" +
									"<property name=\"left_padding\">20</property>" +
									"<property name=\"right_padding\">5</property>" +
									"<child>" +
										"<object class=\"GtkButton\" id=\"go_button\">" +
											"<property name=\"label\" translatable=\"yes\">_Go</property>" +
											"<property name=\"width_request\">71</property>" +
											"<property name=\"visible\">True</property>" +
											"<property name=\"can_focus\">True</property>" +
											"<property name=\"receives_default\">True</property>" +
											"<property name=\"use_underline\">True</property>" +
										"</object>" +
									"</child>" +
								"</object>" +
								"<packing>" +
									"<property name=\"left_attach\">2</property>" +
									"<property name=\"right_attach\">3</property>" +
									"<property name=\"x_options\">GTK_FILL</property>" +
								"</packing>" +
							"</child>" +
							"<child>" +
								"<object class=\"GtkAlignment\" id=\"config_vbox_alignment\">" +
									"<property name=\"visible\">True</property>" +
									"<property name=\"xalign\">1</property>" +
									"<property name=\"xscale\">0</property>" +
									"<property name=\"top_padding\">20</property>" +
									"<property name=\"bottom_padding\">5</property>" +
									"<child>" +
										"<object class=\"GtkVBox\" id=\"config_vbox\">" +
											"<property name=\"visible\">True</property>" +
											"<property name=\"orientation\">vertical</property>" +
											"<child>" +
												"<object class=\"GtkFrame\" id=\"start_frame\">" +
													"<property name=\"visible\">True</property>" +
													"<property name=\"label_xalign\">0</property>" +
													"<property name=\"shadow_type\">none</property>" +
													"<child>" +
														"<object class=\"GtkAlignment\" id=\"start_alignment\">" +
															"<property name=\"visible\">True</property>" +
															"<property name=\"left_padding\">12</property>" +
															"<child>" +
																"<placeholder/>" +
															"</child>" +
														"</object>" +
													"</child>" +
													"<child type=\"label\">" +
														"<object class=\"GtkLabel\" id=\"start_label\">" +
															"<property name=\"visible\">True</property>" +
															"<property name=\"label\" translatable=\"yes\">Start execution trace from:</property>" +
															"<property name=\"use_markup\">True</property>" +
														"</object>" +
														"" +
													"</child>" +
												"</object>" +
												"<packing>" +
													"<property name=\"position\">0</property>" +
												"</packing>" +
											"</child>" +
											"<child>" +
												"<object class=\"GtkFrame\" id=\"stop_frame\">" +
													"<property name=\"visible\">True</property>" +
													"<property name=\"label_xalign\">0</property>" +
													"<property name=\"shadow_type\">none</property>" +
													"<child>" +
														"<object class=\"GtkAlignment\" id=\"stop_alignment\">" +
															"<property name=\"visible\">True</property>" +
															"<property name=\"left_padding\">12</property>" +
															"<child>" +
																"<placeholder/>" +
															"</child>" +
														"</object>" +
													"</child>" +
													"<child type=\"label\">" +
														"<object class=\"GtkLabel\" id=\"stop_label\">" +
															"<property name=\"visible\">True</property>" +
															"<property name=\"label\" translatable=\"yes\">Stop trace at:</property>" +
															"<property name=\"use_markup\">True</property>" +
														"</object>" +
														"" +
													"</child>" +
												"</object>" +
												"<packing>" +
													"<property name=\"position\">1</property>" +
												"</packing>" +
											"</child>" +
										"</object>" +
									"</child>" +
								"</object>" +
								"<packing>" +
									"<property name=\"left_attach\">1</property>" +
									"<property name=\"right_attach\">2</property>" +
									"<property name=\"x_options\">GTK_FILL</property>" +
								"</packing>" +
							"</child>" +
						"</object>" +
					"</child>" +
					"<child type=\"label\">" +
						"<placeholder/>" +
						"" +
					"</child>" +
				"</object>" +
				"<packing>" +
					"<property name=\"expand\">False</property>" +
					"<property name=\"position\">0</property>" +
				"</packing>" +
			"</child>" +
			"<child>" +
				"<object class=\"GtkNotebook\" id=\"content_notebook\">" +
					"<property name=\"visible\">True</property>" +
					"<property name=\"can_focus\">True</property>" +
					"<property name=\"tab_pos\">bottom</property>" +
					"<property name=\"show_border\">False</property>" +
					"<property name=\"tab_border\">0</property>" +
					"<property name=\"tab_hborder\">40</property>" +
					"<property name=\"tab_vborder\">0</property>" +
					"<child>" +
						"<object class=\"GtkAlignment\" id=\"events_alignment\">" +
							"<property name=\"visible\">True</property>" +
							"<property name=\"left_padding\">1</property>" +
							"<property name=\"right_padding\">1</property>" +
							"<child>" +
								"<object class=\"GtkScrolledWindow\" id=\"events_scrollwin\">" +
									"<property name=\"visible\">True</property>" +
									"<property name=\"can_focus\">True</property>" +
									"<property name=\"hscrollbar_policy\">automatic</property>" +
									"<property name=\"vscrollbar_policy\">automatic</property>" +
									"<child>" +
										"<object class=\"GtkTreeView\" id=\"event_view\">" +
											"<property name=\"visible\">True</property>" +
											"<property name=\"can_focus\">True</property>" +
										"</object>" +
									"</child>" +
								"</object>" +
							"</child>" +
						"</object>" +
					"</child>" +
					"<child type=\"tab\">" +
						"<object class=\"GtkLabel\" id=\"function_calls_tab_label\">" +
							"<property name=\"visible\">True</property>" +
							"<property name=\"label\" translatable=\"yes\">Events </property>" +
						"</object>" +
						"<packing>" +
							"<property name=\"tab_fill\">False</property>" +
							"" +
						"</packing>" +
					"</child>" +
					"<child>" +
						"<object class=\"GtkAlignment\" id=\"console_alignment\">" +
							"<property name=\"visible\">True</property>" +
							"<property name=\"bottom_padding\">2</property>" +
							"<property name=\"right_padding\">2</property>" +
							"<child>" +
								"<object class=\"GtkVBox\" id=\"console_vbox\">" +
									"<property name=\"visible\">True</property>" +
									"<property name=\"orientation\">vertical</property>" +
									"<child>" +
										"<object class=\"GtkScrolledWindow\" id=\"console_scrollwin\">" +
											"<property name=\"visible\">True</property>" +
											"<property name=\"can_focus\">True</property>" +
											"<property name=\"hscrollbar_policy\">automatic</property>" +
											"<property name=\"vscrollbar_policy\">automatic</property>" +
											"<child>" +
												"<object class=\"GtkTextView\" id=\"console_view\">" +
													"<property name=\"visible\">True</property>" +
													"<property name=\"can_focus\">True</property>" +
													"<property name=\"editable\">False</property>" +
													"<property name=\"wrap_mode\">word-char</property>" +
													"<property name=\"left_margin\">2</property>" +
													"<property name=\"cursor_visible\">False</property>" +
												"</object>" +
											"</child>" +
										"</object>" +
										"<packing>" +
											"<property name=\"position\">0</property>" +
										"</packing>" +
									"</child>" +
									"<child>" +
										"<object class=\"GtkEntry\" id=\"console_entry\">" +
											"<property name=\"visible\">True</property>" +
											"<property name=\"can_focus\">True</property>" +
											"<property name=\"has_frame\">False</property>" +
											"<property name=\"invisible_char\">●</property>" +
										"</object>" +
										"<packing>" +
											"<property name=\"expand\">False</property>" +
											"<property name=\"position\">1</property>" +
										"</packing>" +
									"</child>" +
								"</object>" +
							"</child>" +
						"</object>" +
						"" +
					"</child>" +
					"<child type=\"tab\">" +
						"<object class=\"GtkLabel\" id=\"debug_tab_label\">" +
							"<property name=\"visible\">True</property>" +
							"<property name=\"label\" translatable=\"yes\">Console </property>" +
						"</object>" +
						"<packing>" +
							"<property name=\"position\">1</property>" +
							"<property name=\"tab_fill\">False</property>" +
							"" +
						"</packing>" +
					"</child>" +
					"<child>" +
						"<placeholder/>" +
					"</child>" +
					"<child type=\"tab\">" +
						"<placeholder/>" +
						"" +
					"</child>" +
				"</object>" +
				"<packing>" +
					"<property name=\"position\">1</property>" +
				"</packing>" +
			"</child>" +
		"</object></interface>";

	public static const string CHAT_XML = "<?xml version=\"1.0\" ?>" +
		"<interface><object class=\"GtkHBox\" id=\"root_hbox\">" +
			"<property name=\"visible\">True</property>" +
			"<property name=\"border_width\">3</property>" +
			"<property name=\"spacing\">5</property>" +
			"<child>" +
				"<object class=\"GtkFrame\" id=\"top_frame\">" +
					"<property name=\"visible\">True</property>" +
					"<property name=\"label_xalign\">0</property>" +
					"<child>" +
						"<object class=\"GtkTreeView\" id=\"roster_treeview\">" +
							"<property name=\"width_request\">120</property>" +
							"<property name=\"visible\">True</property>" +
							"<property name=\"can_focus\">True</property>" +
							"<property name=\"headers_visible\">False</property>" +
						"</object>" +
					"</child>" +
				"</object>" +
				"<packing>" +
					"<property name=\"expand\">False</property>" +
				"</packing>" +
			"</child>" +
			"<child>" +
				"<object class=\"GtkVBox\" id=\"chat_vbox\">" +
					"<property name=\"visible\">True</property>" +
					"<property name=\"spacing\">5</property>" +
					"<child>" +
						"<object class=\"GtkScrolledWindow\" id=\"chat_scrolledwindow\">" +
							"<property name=\"visible\">True</property>" +
							"<property name=\"can_focus\">True</property>" +
							"<property name=\"hscrollbar_policy\">GTK_POLICY_AUTOMATIC</property>" +
							"<property name=\"vscrollbar_policy\">GTK_POLICY_AUTOMATIC</property>" +
							"<property name=\"shadow_type\">GTK_SHADOW_ETCHED_IN</property>" +
							"<child>" +
								"<object class=\"GtkTextView\" id=\"chat_textview\">" +
									"<property name=\"visible\">True</property>" +
									"<property name=\"can_focus\">True</property>" +
									"<property name=\"editable\">False</property>" +
									"<property name=\"wrap_mode\">GTK_WRAP_WORD</property>" +
									"<property name=\"cursor_visible\">False</property>" +
								"</object>" +
							"</child>" +
						"</object>" +
					"</child>" +
					"<child>" +
						"<object class=\"GtkEntry\" id=\"chat_entry\">" +
							"<property name=\"visible\">True</property>" +
							"<property name=\"can_focus\">True</property>" +
						"</object>" +
						"<packing>" +
							"<property name=\"expand\">False</property>" +
							"<property name=\"position\">1</property>" +
						"</packing>" +
					"</child>" +
				"</object>" +
				"<packing>" +
					"<property name=\"position\">1</property>" +
				"</packing>" +
			"</child>" +
		"</object></interface>";

	public static const string HOST_SESSION_XML = "<?xml version=\"1.0\" ?>" +
		"<interface><!-- interface-naming-policy project-wide -->" +
"" +
"<object class=\"GtkHPaned\" id=\"root_hpaned\">" +
			"<property name=\"visible\">True</property>" +
			"<property name=\"can_focus\">True</property>" +
			"<property name=\"position\">215</property>" +
			"<child>" +
				"<object class=\"GtkVBox\" id=\"left_vbox\">" +
					"<property name=\"visible\">True</property>" +
					"<property name=\"orientation\">vertical</property>" +
					"<child>" +
						"<object class=\"GtkButton\" id=\"provider_button\">" +
							"<property name=\"label\" translatable=\"yes\">Choose Provider...</property>" +
							"<property name=\"visible\">True</property>" +
							"<property name=\"can_focus\">True</property>" +
							"<property name=\"receives_default\">True</property>" +
						"</object>" +
						"<packing>" +
							"<property name=\"expand\">False</property>" +
							"<property name=\"position\">0</property>" +
						"</packing>" +
					"</child>" +
					"<child>" +
						"<object class=\"GtkHBox\" id=\"top_hbox\">" +
							"<child>" +
								"<object class=\"GtkEntry\" id=\"pid_entry\">" +
									"<property name=\"visible\">True</property>" +
									"<property name=\"can_focus\">True</property>" +
									"<property name=\"invisible_char\">●</property>" +
								"</object>" +
								"<packing>" +
									"<property name=\"position\">0</property>" +
								"</packing>" +
							"</child>" +
							"<child>" +
								"<object class=\"GtkButton\" id=\"add_button\">" +
									"<property name=\"label\">gtk-add</property>" +
									"<property name=\"visible\">True</property>" +
									"<property name=\"can_focus\">True</property>" +
									"<property name=\"receives_default\">True</property>" +
									"<property name=\"use_stock\">True</property>" +
								"</object>" +
								"<packing>" +
									"<property name=\"expand\">False</property>" +
									"<property name=\"position\">1</property>" +
								"</packing>" +
							"</child>" +
						"</object>" +
						"<packing>" +
							"<property name=\"expand\">False</property>" +
							"<property name=\"position\">1</property>" +
						"</packing>" +
					"</child>" +
					"<child>" +
						"<object class=\"GtkScrolledWindow\" id=\"sessionlist_scrollwin\">" +
							"<property name=\"can_focus\">True</property>" +
							"<property name=\"hscrollbar_policy\">automatic</property>" +
							"<property name=\"vscrollbar_policy\">automatic</property>" +
							"<child>" +
								"<object class=\"GtkTreeView\" id=\"session_treeview\">" +
									"<property name=\"visible\">True</property>" +
									"<property name=\"can_focus\">True</property>" +
								"</object>" +
							"</child>" +
						"</object>" +
						"<packing>" +
							"<property name=\"position\">2</property>" +
						"</packing>" +
					"</child>" +
				"</object>" +
				"<packing>" +
					"<property name=\"resize\">False</property>" +
					"<property name=\"shrink\">True</property>" +
				"</packing>" +
			"</child>" +
			"<child>" +
				"<object class=\"GtkNotebook\" id=\"session_notebook\">" +
					"<property name=\"visible\">True</property>" +
					"<property name=\"can_focus\">True</property>" +
					"<property name=\"tab_pos\">bottom</property>" +
					"<property name=\"show_tabs\">False</property>" +
					"<property name=\"show_border\">False</property>" +
					"<child>" +
						"<placeholder/>" +
					"</child>" +
					"<child type=\"tab\">" +
						"<placeholder/>" +
						"" +
					"</child>" +
				"</object>" +
				"<packing>" +
					"<property name=\"resize\">True</property>" +
					"<property name=\"shrink\">True</property>" +
				"</packing>" +
			"</child>" +
		"</object></interface>";

	public static const string LOGIN_XML = "<?xml version=\"1.0\" ?>" +
		"<interface><object class=\"GtkTable\" id=\"root_table\">" +
			"<property name=\"visible\">True</property>" +
			"<property name=\"n_rows\">4</property>" +
			"<property name=\"n_columns\">2</property>" +
			"<property name=\"column_spacing\">6</property>" +
			"<property name=\"row_spacing\">4</property>" +
			"<child>" +
				"<object class=\"GtkLabel\" id=\"username_label\">" +
					"<property name=\"visible\">True</property>" +
					"<property name=\"xalign\">1</property>" +
					"<property name=\"label\" translatable=\"yes\">Username:</property>" +
				"</object>" +
				"<packing>" +
					"<property name=\"top_attach\">1</property>" +
					"<property name=\"bottom_attach\">2</property>" +
					"<property name=\"y_options\">GTK_FILL</property>" +
				"</packing>" +
			"</child>" +
			"<child>" +
				"<object class=\"GtkLabel\" id=\"password_label\">" +
					"<property name=\"visible\">True</property>" +
					"<property name=\"xalign\">1</property>" +
					"<property name=\"label\" translatable=\"yes\">Password:</property>" +
				"</object>" +
				"<packing>" +
					"<property name=\"top_attach\">2</property>" +
					"<property name=\"bottom_attach\">3</property>" +
					"<property name=\"y_options\"/>" +
				"</packing>" +
			"</child>" +
			"<child>" +
				"<object class=\"GtkLabel\" id=\"welcome_label\">" +
					"<property name=\"visible\">True</property>" +
					"<property name=\"yalign\">0.93000000715255737</property>" +
					"<property name=\"label\" translatable=\"yes\">&lt;span foreground=&quot;blue&quot; size=&quot;xx-large&quot;&gt;Welcome to Frida!&lt;/span&gt;</property>" +
					"<property name=\"use_markup\">True</property>" +
				"</object>" +
				"<packing>" +
					"<property name=\"right_attach\">2</property>" +
				"</packing>" +
			"</child>" +
			"<child>" +
				"<object class=\"GtkAlignment\" id=\"username_alignment\">" +
					"<property name=\"visible\">True</property>" +
					"<property name=\"xalign\">0</property>" +
					"<property name=\"xscale\">0</property>" +
					"<child>" +
						"<object class=\"GtkEntry\" id=\"username_entry\">" +
							"<property name=\"visible\">True</property>" +
							"<property name=\"can_focus\">True</property>" +
							"<property name=\"activates_default\">True</property>" +
						"</object>" +
					"</child>" +
				"</object>" +
				"<packing>" +
					"<property name=\"left_attach\">1</property>" +
					"<property name=\"right_attach\">2</property>" +
					"<property name=\"top_attach\">1</property>" +
					"<property name=\"bottom_attach\">2</property>" +
					"<property name=\"x_options\">GTK_FILL</property>" +
					"<property name=\"y_options\"/>" +
				"</packing>" +
			"</child>" +
			"<child>" +
				"<object class=\"GtkAlignment\" id=\"password_alignment\">" +
					"<property name=\"visible\">True</property>" +
					"<property name=\"xalign\">0</property>" +
					"<property name=\"xscale\">0</property>" +
					"<child>" +
						"<object class=\"GtkEntry\" id=\"password_entry\">" +
							"<property name=\"visible\">True</property>" +
							"<property name=\"can_focus\">True</property>" +
							"<property name=\"activates_default\">True</property>" +
						"</object>" +
					"</child>" +
				"</object>" +
				"<packing>" +
					"<property name=\"left_attach\">1</property>" +
					"<property name=\"right_attach\">2</property>" +
					"<property name=\"top_attach\">2</property>" +
					"<property name=\"bottom_attach\">3</property>" +
					"<property name=\"y_options\">GTK_FILL</property>" +
				"</packing>" +
			"</child>" +
			"<child>" +
				"<object class=\"GtkAlignment\" id=\"signin_alignment\">" +
					"<property name=\"visible\">True</property>" +
					"<property name=\"yalign\">0.05000000074505806</property>" +
					"<property name=\"xscale\">0.039999999105930328</property>" +
					"<property name=\"yscale\">0.019999999552965164</property>" +
					"<child>" +
						"<object class=\"GtkButton\" id=\"sign_in_button\">" +
							"<property name=\"visible\">True</property>" +
							"<property name=\"can_focus\">True</property>" +
							"<property name=\"can_default\">True</property>" +
							"<property name=\"receives_default\">True</property>" +
							"<property name=\"label\" translatable=\"yes\">Sign In</property>" +
						"</object>" +
					"</child>" +
				"</object>" +
				"<packing>" +
					"<property name=\"right_attach\">2</property>" +
					"<property name=\"top_attach\">3</property>" +
					"<property name=\"bottom_attach\">4</property>" +
				"</packing>" +
			"</child>" +
		"</object></interface>";

	public static const string WORKSPACE_XML = "<?xml version=\"1.0\" ?>" +
		"<interface><!-- interface-naming-policy toplevel-contextual -->" +
"" +
"<object class=\"GtkVBox\" id=\"root_vbox\">" +
			"<property name=\"visible\">True</property>" +
			"<property name=\"orientation\">vertical</property>" +
			"<child>" +
				"<object class=\"GtkVPaned\" id=\"vpaned\">" +
					"<property name=\"visible\">True</property>" +
					"<property name=\"can_focus\">True</property>" +
					"<property name=\"orientation\">vertical</property>" +
					"<property name=\"position\">370</property>" +
					"<property name=\"position_set\">True</property>" +
					"<child>" +
						"<object class=\"GtkFrame\" id=\"top_frame\">" +
							"<property name=\"visible\">True</property>" +
							"<property name=\"label_xalign\">0</property>" +
							"<property name=\"shadow_type\">in</property>" +
						"</object>" +
						"<packing>" +
							"<property name=\"resize\">False</property>" +
							"<property name=\"shrink\">True</property>" +
						"</packing>" +
					"</child>" +
					"<child>" +
						"<object class=\"GtkFrame\" id=\"bottom_frame\">" +
							"<property name=\"visible\">True</property>" +
							"<property name=\"label_xalign\">0</property>" +
							"<property name=\"shadow_type\">in</property>" +
						"</object>" +
						"<packing>" +
							"<property name=\"resize\">True</property>" +
							"<property name=\"shrink\">True</property>" +
						"</packing>" +
					"</child>" +
				"</object>" +
				"<packing>" +
					"<property name=\"position\">0</property>" +
				"</packing>" +
			"</child>" +
			"<child>" +
				"<object class=\"GtkStatusbar\" id=\"statusbar\">" +
					"<property name=\"visible\">True</property>" +
					"<property name=\"spacing\">2</property>" +
				"</object>" +
				"<packing>" +
					"<property name=\"expand\">False</property>" +
					"<property name=\"position\">1</property>" +
				"</packing>" +
			"</child>" +
		"</object></interface>";
}