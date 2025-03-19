# -*- coding: utf-8 -*-
import difflib
import json
import os
import sys
import typing

from loguru import logger
import openai
from openai import OpenAI
from tree_sitter import Language, Parser
import tempfile
import subprocess

openai.api_key = ""
openai.base_url = ''
client = OpenAI(api_key=openai.api_key, base_url=openai.base_url)


def get_response(question):
    response = client.chat.completions.create(
        # model="gpt-4o-2024-05-13",
        # model="gemini-1.5-flash-002",
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are now playing the role of a vulnerability repair expert."},
            {"role": "user", "content": question},
        ],
    )
    text = response.choices[0].message.content
    return text


Language.build_library(

    # Store the library in the `build` directory
    '../tree-sitter/build/my-languages.so',

    # Include one or more languages
    [
        '../tree-sitter/vendor/tree-sitter-c',
    ]
)

C_LANGUAGE = Language('../tree-sitter/build/my-languages.so', 'c')

with open('../prompt/repair_function.txt', 'r', encoding='utf-8') as f:
    repair_function = f.read()

# with open('../prompt/repair_block.txt', 'r', encoding='utf-8') as f:
#     repair_block = f.read()

with open('../prompt/iterative_function.txt', 'r', encoding='utf-8') as f:
    iterative_function = f.read()

prompt_example = {
    'Out-of-bounds Read': [
        {
            "func": "static int\ncmdline_insert_reg(int *gotesc UNUSED)\n{\n    int\t\ti;\n    int\t\tc;\n    int\t\tsave_new_cmdpos = new_cmdpos;\n\n#ifdef USE_ON_FLY_SCROLL\n    dont_scroll = TRUE;\t// disallow scrolling here\n#endif\n    putcmdline('\"', TRUE);\n    ++no_mapping;\n    ++allow_keys;\n    i = c = plain_vgetc();\t// CTRL-R <char>\n    if (i == Ctrl_O)\n\ti = Ctrl_R;\t\t// CTRL-R CTRL-O == CTRL-R CTRL-R\n    if (i == Ctrl_R)\n\tc = plain_vgetc();\t// CTRL-R CTRL-R <char>\n    extra_char = NUL;\n    --no_mapping;\n    --allow_keys;\n#ifdef FEAT_EVAL\n    /*\n     * Insert the result of an expression.\n     */\n    new_cmdpos = -1;\n    if (c == '=')\n    {\n\tif (ccline.cmdfirstc == '='  // can't do this recursively\n\t\t|| cmdline_star > 0) // or when typing a password\n\t{\n\t    beep_flush();\n\t    c = ESC;\n\t}\n\telse\n\t    c = get_expr_register();\n    }\n#endif\n    if (c != ESC)\t    // use ESC to cancel inserting register\n    {\n\tcmdline_paste(c, i == Ctrl_R, FALSE);\n\n#ifdef FEAT_EVAL\n\t// When there was a serious error abort getting the\n\t// command line.\n\tif (aborting())\n\t{\n\t    *gotesc = TRUE;  // will free ccline.cmdbuff after\n\t    // putting it in history\n\t    return GOTO_NORMAL_MODE;\n\t}\n#endif\n\tKeyTyped = FALSE;\t// Don't do p_wc completion.\n#ifdef FEAT_EVAL\n\tif (new_cmdpos >= 0)\n\t{\n\t    // set_cmdline_pos() was used\n\t    if (new_cmdpos > ccline.cmdlen)\n\t\tccline.cmdpos = ccline.cmdlen;\n\t    else\n\t\tccline.cmdpos = new_cmdpos;\n\t}\n#endif\n    }\n    new_cmdpos = save_new_cmdpos;\n\n    // remove the double quote\n    redrawcmd();\n\n    // The text has been stuffed, the command line didn't change yet.\n    return CMDLINE_NOT_CHANGED;\n}",
            "func_before": "static int\ncmdline_insert_reg(int *gotesc UNUSED)\n{\n    int\t\ti;\n    int\t\tc;\n\n#ifdef USE_ON_FLY_SCROLL\n    dont_scroll = TRUE;\t// disallow scrolling here\n#endif\n    putcmdline('\"', TRUE);\n    ++no_mapping;\n    ++allow_keys;\n    i = c = plain_vgetc();\t// CTRL-R <char>\n    if (i == Ctrl_O)\n\ti = Ctrl_R;\t\t// CTRL-R CTRL-O == CTRL-R CTRL-R\n    if (i == Ctrl_R)\n\tc = plain_vgetc();\t// CTRL-R CTRL-R <char>\n    extra_char = NUL;\n    --no_mapping;\n    --allow_keys;\n#ifdef FEAT_EVAL\n    /*\n     * Insert the result of an expression.\n     * Need to save the current command line, to be able to enter\n     * a new one...\n     */\n    new_cmdpos = -1;\n    if (c == '=')\n    {\n\tif (ccline.cmdfirstc == '='  // can't do this recursively\n\t\t|| cmdline_star > 0) // or when typing a password\n\t{\n\t    beep_flush();\n\t    c = ESC;\n\t}\n\telse\n\t    c = get_expr_register();\n    }\n#endif\n    if (c != ESC)\t    // use ESC to cancel inserting register\n    {\n\tcmdline_paste(c, i == Ctrl_R, FALSE);\n\n#ifdef FEAT_EVAL\n\t// When there was a serious error abort getting the\n\t// command line.\n\tif (aborting())\n\t{\n\t    *gotesc = TRUE;  // will free ccline.cmdbuff after\n\t    // putting it in history\n\t    return GOTO_NORMAL_MODE;\n\t}\n#endif\n\tKeyTyped = FALSE;\t// Don't do p_wc completion.\n#ifdef FEAT_EVAL\n\tif (new_cmdpos >= 0)\n\t{\n\t    // set_cmdline_pos() was used\n\t    if (new_cmdpos > ccline.cmdlen)\n\t\tccline.cmdpos = ccline.cmdlen;\n\t    else\n\t\tccline.cmdpos = new_cmdpos;\n\t}\n#endif\n    }\n    // remove the double quote\n    redrawcmd();\n\n    // The text has been stuffed, the command line didn't change yet.\n    return CMDLINE_NOT_CHANGED;\n}",
        },
        {
            "func": "static int\nfind_sig8_target_as_global_offset(Dwarf_Attribute attr,\n    Dwarf_Sig8  *sig8,\n    Dwarf_Bool  *is_info,\n    Dwarf_Off   *targoffset,\n    Dwarf_Error *error)\n{\n    Dwarf_Die  targdie = 0;\n    Dwarf_Bool targ_is_info = 0;\n    Dwarf_Off  localoff = 0;\n    int res = 0;\n    targ_is_info = attr->ar_cu_context->cc_is_info;\n    memcpy(sig8,attr->ar_debug_ptr,sizeof(*sig8));\n    res = dwarf_find_die_given_sig8(attr->ar_dbg,\n        sig8,&targdie,&targ_is_info,error);\n    if (res != DW_DLV_OK) {\n        return res;\n    }\n    res = dwarf_die_offsets(targdie,targoffset,&localoff,error);\n    if (res != DW_DLV_OK) {\n        dwarf_dealloc_die(targdie);\n        return res;\n    }\n    *is_info = targdie->di_cu_context->cc_is_info;\n    dwarf_dealloc_die(targdie);\n    return DW_DLV_OK;\n}",
            "func_before": "static int\nfind_sig8_target_as_global_offset(Dwarf_Attribute attr,\n    Dwarf_Sig8  *sig8,\n    Dwarf_Bool  *is_info,\n    Dwarf_Off   *targoffset,\n    Dwarf_Error *error)\n{\n    Dwarf_Die  targdie = 0;\n    Dwarf_Bool targ_is_info = 0;\n    Dwarf_Off  localoff = 0;\n    int res = 0;\n\n    targ_is_info = attr->ar_cu_context->cc_is_info;\n    memcpy(sig8,attr->ar_debug_ptr,sizeof(*sig8));\n    res = dwarf_find_die_given_sig8(attr->ar_dbg,\n        sig8,&targdie,&targ_is_info,error);\n    if (res != DW_DLV_OK) {\n        return res;\n    }\n    res = dwarf_die_offsets(targdie,targoffset,&localoff,error);\n    if (res != DW_DLV_OK) {\n        dwarf_dealloc_die(targdie);\n        return res;\n    }\n    *is_info = targdie->di_cu_context->cc_is_info;\n    dwarf_dealloc_die(targdie);\n    return DW_DLV_OK;\n}",
        },
        {
            "func": "void\ncheck_shellsize(void)\n{\n    if (Rows < min_rows())\t// need room for one window and command line\n\tRows = min_rows();\n    limit_screen_size();\n\n    // make sure these values are not invalid\n    if (cmdline_row >= Rows)\n\tcmdline_row = Rows - 1;\n    if (msg_row >= Rows)\n\tmsg_row = Rows - 1;\n}",
            "func_before": "void\ncheck_shellsize(void)\n{\n    if (Rows < min_rows())\t// need room for one window and command line\n\tRows = min_rows();\n    limit_screen_size();\n}",
        }
    ],
    'Out-of-bounds Write': [
        {
            "func": "METHODDEF(JDIMENSION)\nget_word_rgb_row(j_compress_ptr cinfo, cjpeg_source_ptr sinfo)\n/* This version is for reading raw-word-format PPM files with any maxval */\n{\n  ppm_source_ptr source = (ppm_source_ptr)sinfo;\n  register JSAMPROW ptr;\n  register U_CHAR *bufferptr;\n  register JSAMPLE *rescale = source->rescale;\n  JDIMENSION col;\n  unsigned int maxval = source->maxval;\n  register int rindex = rgb_red[cinfo->in_color_space];\n  register int gindex = rgb_green[cinfo->in_color_space];\n  register int bindex = rgb_blue[cinfo->in_color_space];\n  register int aindex = alpha_index[cinfo->in_color_space];\n  register int ps = rgb_pixelsize[cinfo->in_color_space];\n\n  if (!ReadOK(source->pub.input_file, source->iobuffer, source->buffer_width))\n    ERREXIT(cinfo, JERR_INPUT_EOF);\n  ptr = source->pub.buffer[0];\n  bufferptr = source->iobuffer;\n  for (col = cinfo->image_width; col > 0; col--) {\n    register unsigned int temp;\n    temp  = UCH(*bufferptr++) << 8;\n    temp |= UCH(*bufferptr++);\n    if (temp > maxval)\n      ERREXIT(cinfo, JERR_PPM_OUTOFRANGE);\n    ptr[rindex] = rescale[temp];\n    temp  = UCH(*bufferptr++) << 8;\n    temp |= UCH(*bufferptr++);\n    if (temp > maxval)\n      ERREXIT(cinfo, JERR_PPM_OUTOFRANGE);\n    ptr[gindex] = rescale[temp];\n    temp  = UCH(*bufferptr++) << 8;\n    temp |= UCH(*bufferptr++);\n    if (temp > maxval)\n      ERREXIT(cinfo, JERR_PPM_OUTOFRANGE);\n    ptr[bindex] = rescale[temp];\n    if (aindex >= 0)\n      ptr[aindex] = 0xFF;\n    ptr += ps;\n  }\n  return 1;\n}",
            "func_before": "METHODDEF(JDIMENSION)\nget_word_rgb_row(j_compress_ptr cinfo, cjpeg_source_ptr sinfo)\n/* This version is for reading raw-word-format PPM files with any maxval */\n{\n  ppm_source_ptr source = (ppm_source_ptr)sinfo;\n  register JSAMPROW ptr;\n  register U_CHAR *bufferptr;\n  register JSAMPLE *rescale = source->rescale;\n  JDIMENSION col;\n  unsigned int maxval = source->maxval;\n\n  if (!ReadOK(source->pub.input_file, source->iobuffer, source->buffer_width))\n    ERREXIT(cinfo, JERR_INPUT_EOF);\n  ptr = source->pub.buffer[0];\n  bufferptr = source->iobuffer;\n  for (col = cinfo->image_width; col > 0; col--) {\n    register unsigned int temp;\n    temp  = UCH(*bufferptr++) << 8;\n    temp |= UCH(*bufferptr++);\n    if (temp > maxval)\n      ERREXIT(cinfo, JERR_PPM_OUTOFRANGE);\n    *ptr++ = rescale[temp];\n    temp  = UCH(*bufferptr++) << 8;\n    temp |= UCH(*bufferptr++);\n    if (temp > maxval)\n      ERREXIT(cinfo, JERR_PPM_OUTOFRANGE);\n    *ptr++ = rescale[temp];\n    temp  = UCH(*bufferptr++) << 8;\n    temp |= UCH(*bufferptr++);\n    if (temp > maxval)\n      ERREXIT(cinfo, JERR_PPM_OUTOFRANGE);\n    *ptr++ = rescale[temp];\n  }\n  return 1;\n}",
        },
        {
            "func": "static int hevc_frame_start(HEVCContext *s)\n{\n    HEVCLocalContext *lc = &s->HEVClc;\n    int ret;\n\n    memset(s->horizontal_bs, 0, 2 * s->bs_width * (s->bs_height + 1));\n    memset(s->vertical_bs,   0, 2 * s->bs_width * (s->bs_height + 1));\n    memset(s->cbf_luma,      0, s->sps->min_tb_width * s->sps->min_tb_height);\n    memset(s->is_pcm,        0, s->sps->min_pu_width * s->sps->min_pu_height);\n\n    lc->start_of_tiles_x = 0;\n    s->is_decoded        = 0;\n    s->first_nal_type    = s->nal_unit_type;\n\n    if (s->pps->tiles_enabled_flag)\n        lc->end_of_tiles_x = s->pps->column_width[0] << s->sps->log2_ctb_size;\n\n    ret = ff_hevc_set_new_ref(s, s->sps->sao_enabled ? &s->sao_frame : &s->frame,\n                              s->poc);\n    if (ret < 0)\n        goto fail;\n\n    ret = ff_hevc_frame_rps(s);\n    if (ret < 0) {\n        av_log(s->avctx, AV_LOG_ERROR, \"Error constructing the frame RPS.\\n\");\n        goto fail;\n    }\n\n    ret = set_side_data(s);\n    if (ret < 0)\n        goto fail;\n\n    av_frame_unref(s->output_frame);\n    ret = ff_hevc_output_frame(s, s->output_frame, 0);\n    if (ret < 0)\n        goto fail;\n\n    ff_thread_finish_setup(s->avctx);\n\n    return 0;\n\nfail:\n    if (s->ref)\n        ff_thread_report_progress(&s->ref->tf, INT_MAX, 0);\n    s->ref = NULL;\n    return ret;\n}",
            "func_before": "static int hevc_frame_start(HEVCContext *s)\n{\n    HEVCLocalContext *lc = &s->HEVClc;\n    int ret;\n\n    memset(s->horizontal_bs, 0, 2 * s->bs_width * (s->bs_height + 1));\n    memset(s->vertical_bs,   0, 2 * s->bs_width * (s->bs_height + 1));\n    memset(s->cbf_luma,      0, s->sps->min_tb_width * s->sps->min_tb_height);\n    memset(s->is_pcm,        0, s->sps->min_pu_width * s->sps->min_pu_height);\n\n    lc->start_of_tiles_x = 0;\n    s->is_decoded        = 0;\n\n    if (s->pps->tiles_enabled_flag)\n        lc->end_of_tiles_x = s->pps->column_width[0] << s->sps->log2_ctb_size;\n\n    ret = ff_hevc_set_new_ref(s, s->sps->sao_enabled ? &s->sao_frame : &s->frame,\n                              s->poc);\n    if (ret < 0)\n        goto fail;\n\n    ret = ff_hevc_frame_rps(s);\n    if (ret < 0) {\n        av_log(s->avctx, AV_LOG_ERROR, \"Error constructing the frame RPS.\\n\");\n        goto fail;\n    }\n\n    ret = set_side_data(s);\n    if (ret < 0)\n        goto fail;\n\n    av_frame_unref(s->output_frame);\n    ret = ff_hevc_output_frame(s, s->output_frame, 0);\n    if (ret < 0)\n        goto fail;\n\n    ff_thread_finish_setup(s->avctx);\n\n    return 0;\n\nfail:\n    if (s->ref)\n        ff_thread_report_progress(&s->ref->tf, INT_MAX, 0);\n    s->ref = NULL;\n    return ret;\n}",
        },
        {
            "func": "static int cmv_process_header(CmvContext *s, const uint8_t *buf, const uint8_t *buf_end)\n{\n    int pal_start, pal_count, i, ret, fps;\n\n    if(buf_end - buf < 16) {\n        av_log(s->avctx, AV_LOG_WARNING, \"truncated header\\n\");\n        return AVERROR_INVALIDDATA;\n    }\n\n    s->width  = AV_RL16(&buf[4]);\n    s->height = AV_RL16(&buf[6]);\n\n    if (s->width  != s->avctx->width ||\n        s->height != s->avctx->height) {\n        av_frame_unref(s->last_frame);\n        av_frame_unref(s->last2_frame);\n    }\n\n    ret = ff_set_dimensions(s->avctx, s->width, s->height);\n    if (ret < 0)\n        return ret;\n\n    fps = AV_RL16(&buf[10]);\n    if (fps > 0)\n        s->avctx->time_base = (AVRational){ 1, fps };\n\n    pal_start = AV_RL16(&buf[12]);\n    pal_count = AV_RL16(&buf[14]);\n\n    buf += 16;\n    for (i=pal_start; i<pal_start+pal_count && i<AVPALETTE_COUNT && buf_end - buf >= 3; i++) {\n        s->palette[i] = AV_RB24(buf);\n        buf += 3;\n    }\n\n    return 0;\n}",
            "func_before": "static int cmv_process_header(CmvContext *s, const uint8_t *buf, const uint8_t *buf_end)\n{\n    int pal_start, pal_count, i, ret, fps;\n\n    if(buf_end - buf < 16) {\n        av_log(s->avctx, AV_LOG_WARNING, \"truncated header\\n\");\n        return AVERROR_INVALIDDATA;\n    }\n\n    s->width  = AV_RL16(&buf[4]);\n    s->height = AV_RL16(&buf[6]);\n\n    ret = ff_set_dimensions(s->avctx, s->width, s->height);\n    if (ret < 0)\n        return ret;\n\n    fps = AV_RL16(&buf[10]);\n    if (fps > 0)\n        s->avctx->time_base = (AVRational){ 1, fps };\n\n    pal_start = AV_RL16(&buf[12]);\n    pal_count = AV_RL16(&buf[14]);\n\n    buf += 16;\n    for (i=pal_start; i<pal_start+pal_count && i<AVPALETTE_COUNT && buf_end - buf >= 3; i++) {\n        s->palette[i] = AV_RB24(buf);\n        buf += 3;\n    }\n\n    return 0;\n}",
        }
    ],
    'memory read from null pointer': [
        {
            "func": "void\ndiff_redraw(\n    int\t\tdofold)\t    // also recompute the folds\n{\n    win_T\t*wp;\n    win_T\t*wp_other = NULL;\n    int\t\tused_max_fill_other = FALSE;\n    int\t\tused_max_fill_curwin = FALSE;\n    int\t\tn;\n\n    need_diff_redraw = FALSE;\n    FOR_ALL_WINDOWS(wp)\n\t// when closing windows or wiping buffers skip invalid window\n\tif (wp->w_p_diff && buf_valid(wp->w_buffer))\n\t{\n\t    redraw_win_later(wp, SOME_VALID);\n\t    if (wp != curwin)\n\t\twp_other = wp;\n#ifdef FEAT_FOLDING\n\t    if (dofold && foldmethodIsDiff(wp))\n\t\tfoldUpdateAll(wp);\n#endif\n\t    // A change may have made filler lines invalid, need to take care\n\t    // of that for other windows.\n\t    n = diff_check(wp, wp->w_topline);\n\t    if ((wp != curwin && wp->w_topfill > 0) || n > 0)\n\t    {\n\t\tif (wp->w_topfill > n)\n\t\t    wp->w_topfill = (n < 0 ? 0 : n);\n\t\telse if (n > 0 && n > wp->w_topfill)\n\t\t{\n\t\t    wp->w_topfill = n;\n\t\t    if (wp == curwin)\n\t\t\tused_max_fill_curwin = TRUE;\n\t\t    else if (wp_other != NULL)\n\t\t\tused_max_fill_other = TRUE;\n\t\t}\n\t\tcheck_topfill(wp, FALSE);\n\t    }\n\t}\n\n    if (wp_other != NULL && curwin->w_p_scb)\n    {\n\tif (used_max_fill_curwin)\n\t    // The current window was set to use the maximum number of filler\n\t    // lines, may need to reduce them.\n\t    diff_set_topline(wp_other, curwin);\n\telse if (used_max_fill_other)\n\t    // The other window was set to use the maximum number of filler\n\t    // lines, may need to reduce them.\n\t    diff_set_topline(curwin, wp_other);\n    }\n}",
            "func_before": "void\ndiff_redraw(\n    int\t\tdofold)\t    // also recompute the folds\n{\n    win_T\t*wp;\n    win_T\t*wp_other = NULL;\n    int\t\tused_max_fill_other = FALSE;\n    int\t\tused_max_fill_curwin = FALSE;\n    int\t\tn;\n\n    need_diff_redraw = FALSE;\n    FOR_ALL_WINDOWS(wp)\n\tif (wp->w_p_diff)\n\t{\n\t    redraw_win_later(wp, SOME_VALID);\n\t    if (wp != curwin)\n\t\twp_other = wp;\n#ifdef FEAT_FOLDING\n\t    if (dofold && foldmethodIsDiff(wp))\n\t\tfoldUpdateAll(wp);\n#endif\n\t    // A change may have made filler lines invalid, need to take care\n\t    // of that for other windows.\n\t    n = diff_check(wp, wp->w_topline);\n\t    if ((wp != curwin && wp->w_topfill > 0) || n > 0)\n\t    {\n\t\tif (wp->w_topfill > n)\n\t\t    wp->w_topfill = (n < 0 ? 0 : n);\n\t\telse if (n > 0 && n > wp->w_topfill)\n\t\t{\n\t\t    wp->w_topfill = n;\n\t\t    if (wp == curwin)\n\t\t\tused_max_fill_curwin = TRUE;\n\t\t    else if (wp_other != NULL)\n\t\t\tused_max_fill_other = TRUE;\n\t\t}\n\t\tcheck_topfill(wp, FALSE);\n\t    }\n\t}\n\n    if (wp_other != NULL && curwin->w_p_scb)\n    {\n\tif (used_max_fill_curwin)\n\t    // The current window was set to use the maximum number of filler\n\t    // lines, may need to reduce them.\n\t    diff_set_topline(wp_other, curwin);\n\telse if (used_max_fill_other)\n\t    // The other window was set to use the maximum number of filler\n\t    // lines, may need to reduce them.\n\t    diff_set_topline(curwin, wp_other);\n    }\n}",
        },
        {
            "func": "OFBool\nDU_getStringDOElement(DcmItem *obj, DcmTagKey t, char *s, size_t bufsize)\n{\n    DcmByteString *elem;\n    DcmStack stack;\n    OFCondition ec = EC_Normal;\n    char* aString;\n\n    ec = obj->search(t, stack);\n    elem = (DcmByteString*) stack.top();\n    if (ec == EC_Normal && elem != NULL) {\n        if (elem->getLength() == 0) {\n            s[0] = '\\0';\n        } else {\n            ec =  elem->getString(aString);\n            if (ec == EC_Normal)\n                OFStandard::strlcpy(s, aString, bufsize);\n        }\n    }\n    return (ec == EC_Normal);\n}",
            "func_before": "OFBool\nDU_getStringDOElement(DcmItem *obj, DcmTagKey t, char *s, size_t bufsize)\n{\n    DcmByteString *elem;\n    DcmStack stack;\n    OFCondition ec = EC_Normal;\n    char* aString;\n\n    ec = obj->search(t, stack);\n    elem = (DcmByteString*) stack.top();\n    if (ec == EC_Normal && elem != NULL) {\n        if (elem->getLength() == 0) {\n            s[0] = '\\0';\n        } else {\n            ec =  elem->getString(aString);\n            OFStandard::strlcpy(s, aString, bufsize);\n        }\n    }\n    return (ec == EC_Normal);\n}",
        },
        {
            "func": "int x86_decode_emulated_instruction(struct kvm_vcpu *vcpu, int emulation_type,\n\t\t\t\t    void *insn, int insn_len)\n{\n\tstruct x86_emulate_ctxt *ctxt = vcpu->arch.emulate_ctxt;\n\tint r;\n\n\tinit_emulate_ctxt(vcpu);\n\n\tr = x86_decode_insn(ctxt, insn, insn_len, emulation_type);\n\n\ttrace_kvm_emulate_insn_start(vcpu);\n\t++vcpu->stat.insn_emulation;\n\n\treturn r;\n}",
            "func_before": "int x86_decode_emulated_instruction(struct kvm_vcpu *vcpu, int emulation_type,\n\t\t\t\t    void *insn, int insn_len)\n{\n\tint r = EMULATION_OK;\n\tstruct x86_emulate_ctxt *ctxt = vcpu->arch.emulate_ctxt;\n\n\tinit_emulate_ctxt(vcpu);\n\n\t/*\n\t * We will reenter on the same instruction since we do not set\n\t * complete_userspace_io. This does not handle watchpoints yet,\n\t * those would be handled in the emulate_ops.\n\t */\n\tif (!(emulation_type & EMULTYPE_SKIP) &&\n\t    kvm_vcpu_check_breakpoint(vcpu, &r))\n\t\treturn r;\n\n\tr = x86_decode_insn(ctxt, insn, insn_len, emulation_type);\n\n\ttrace_kvm_emulate_insn_start(vcpu);\n\t++vcpu->stat.insn_emulation;\n\n\treturn r;\n}",
        }
    ],
    'division by zero': [
        {
            "func": "static int set_geometry(unsigned int cmd, struct floppy_struct *g,\n\t\t\t       int drive, int type, struct block_device *bdev)\n{\n\tint cnt;\n\n\t/* sanity checking for parameters. */\n\tif (g->sect <= 0 ||\n\t    g->head <= 0 ||\n\t    /* check for zero in F_SECT_PER_TRACK */\n\t    (unsigned char)((g->sect << 2) >> FD_SIZECODE(g)) == 0 ||\n\t    g->track <= 0 || g->track > UDP->tracks >> STRETCH(g) ||\n\t    /* check if reserved bits are set */\n\t    (g->stretch & ~(FD_STRETCH | FD_SWAPSIDES | FD_SECTBASEMASK)) != 0)\n\t\treturn -EINVAL;\n\tif (type) {\n\t\tif (!capable(CAP_SYS_ADMIN))\n\t\t\treturn -EPERM;\n\t\tmutex_lock(&open_lock);\n\t\tif (lock_fdc(drive)) {\n\t\t\tmutex_unlock(&open_lock);\n\t\t\treturn -EINTR;\n\t\t}\n\t\tfloppy_type[type] = *g;\n\t\tfloppy_type[type].name = \"user format\";\n\t\tfor (cnt = type << 2; cnt < (type << 2) + 4; cnt++)\n\t\t\tfloppy_sizes[cnt] = floppy_sizes[cnt + 0x80] =\n\t\t\t    floppy_type[type].size + 1;\n\t\tprocess_fd_request();\n\t\tfor (cnt = 0; cnt < N_DRIVE; cnt++) {\n\t\t\tstruct block_device *bdev = opened_bdev[cnt];\n\t\t\tif (!bdev || ITYPE(drive_state[cnt].fd_device) != type)\n\t\t\t\tcontinue;\n\t\t\t__invalidate_device(bdev, true);\n\t\t}\n\t\tmutex_unlock(&open_lock);\n\t} else {\n\t\tint oldStretch;\n\n\t\tif (lock_fdc(drive))\n\t\t\treturn -EINTR;\n\t\tif (cmd != FDDEFPRM) {\n\t\t\t/* notice a disk change immediately, else\n\t\t\t * we lose our settings immediately*/\n\t\t\tif (poll_drive(true, FD_RAW_NEED_DISK) == -EINTR)\n\t\t\t\treturn -EINTR;\n\t\t}\n\t\toldStretch = g->stretch;\n\t\tuser_params[drive] = *g;\n\t\tif (buffer_drive == drive)\n\t\t\tSUPBOUND(buffer_max, user_params[drive].sect);\n\t\tcurrent_type[drive] = &user_params[drive];\n\t\tfloppy_sizes[drive] = user_params[drive].size;\n\t\tif (cmd == FDDEFPRM)\n\t\t\tDRS->keep_data = -1;\n\t\telse\n\t\t\tDRS->keep_data = 1;\n\t\t/* invalidation. Invalidate only when needed, i.e.\n\t\t * when there are already sectors in the buffer cache\n\t\t * whose number will change. This is useful, because\n\t\t * mtools often changes the geometry of the disk after\n\t\t * looking at the boot block */\n\t\tif (DRS->maxblock > user_params[drive].sect ||\n\t\t    DRS->maxtrack ||\n\t\t    ((user_params[drive].sect ^ oldStretch) &\n\t\t     (FD_SWAPSIDES | FD_SECTBASEMASK)))\n\t\t\tinvalidate_drive(bdev);\n\t\telse\n\t\t\tprocess_fd_request();\n\t}\n\treturn 0;\n}",
            "func_before": "static int set_geometry(unsigned int cmd, struct floppy_struct *g,\n\t\t\t       int drive, int type, struct block_device *bdev)\n{\n\tint cnt;\n\n\t/* sanity checking for parameters. */\n\tif (g->sect <= 0 ||\n\t    g->head <= 0 ||\n\t    g->track <= 0 || g->track > UDP->tracks >> STRETCH(g) ||\n\t    /* check if reserved bits are set */\n\t    (g->stretch & ~(FD_STRETCH | FD_SWAPSIDES | FD_SECTBASEMASK)) != 0)\n\t\treturn -EINVAL;\n\tif (type) {\n\t\tif (!capable(CAP_SYS_ADMIN))\n\t\t\treturn -EPERM;\n\t\tmutex_lock(&open_lock);\n\t\tif (lock_fdc(drive)) {\n\t\t\tmutex_unlock(&open_lock);\n\t\t\treturn -EINTR;\n\t\t}\n\t\tfloppy_type[type] = *g;\n\t\tfloppy_type[type].name = \"user format\";\n\t\tfor (cnt = type << 2; cnt < (type << 2) + 4; cnt++)\n\t\t\tfloppy_sizes[cnt] = floppy_sizes[cnt + 0x80] =\n\t\t\t    floppy_type[type].size + 1;\n\t\tprocess_fd_request();\n\t\tfor (cnt = 0; cnt < N_DRIVE; cnt++) {\n\t\t\tstruct block_device *bdev = opened_bdev[cnt];\n\t\t\tif (!bdev || ITYPE(drive_state[cnt].fd_device) != type)\n\t\t\t\tcontinue;\n\t\t\t__invalidate_device(bdev, true);\n\t\t}\n\t\tmutex_unlock(&open_lock);\n\t} else {\n\t\tint oldStretch;\n\n\t\tif (lock_fdc(drive))\n\t\t\treturn -EINTR;\n\t\tif (cmd != FDDEFPRM) {\n\t\t\t/* notice a disk change immediately, else\n\t\t\t * we lose our settings immediately*/\n\t\t\tif (poll_drive(true, FD_RAW_NEED_DISK) == -EINTR)\n\t\t\t\treturn -EINTR;\n\t\t}\n\t\toldStretch = g->stretch;\n\t\tuser_params[drive] = *g;\n\t\tif (buffer_drive == drive)\n\t\t\tSUPBOUND(buffer_max, user_params[drive].sect);\n\t\tcurrent_type[drive] = &user_params[drive];\n\t\tfloppy_sizes[drive] = user_params[drive].size;\n\t\tif (cmd == FDDEFPRM)\n\t\t\tDRS->keep_data = -1;\n\t\telse\n\t\t\tDRS->keep_data = 1;\n\t\t/* invalidation. Invalidate only when needed, i.e.\n\t\t * when there are already sectors in the buffer cache\n\t\t * whose number will change. This is useful, because\n\t\t * mtools often changes the geometry of the disk after\n\t\t * looking at the boot block */\n\t\tif (DRS->maxblock > user_params[drive].sect ||\n\t\t    DRS->maxtrack ||\n\t\t    ((user_params[drive].sect ^ oldStretch) &\n\t\t     (FD_SWAPSIDES | FD_SECTBASEMASK)))\n\t\t\tinvalidate_drive(bdev);\n\t\telse\n\t\t\tprocess_fd_request();\n\t}\n\treturn 0;\n}",
        },
        {
            "func": "bool HOGDescriptor::read(FileNode& obj)\n{\n    CV_Assert(!obj[\"winSize\"].empty());\n\n    if( !obj.isMap() )\n        return false;\n    FileNodeIterator it = obj[\"winSize\"].begin();\n    it >> winSize.width >> winSize.height; CV_Assert(!winSize.empty());\n    it = obj[\"blockSize\"].begin();\n    it >> blockSize.width >> blockSize.height; CV_Assert(!blockSize.empty());\n    it = obj[\"blockStride\"].begin();\n    it >> blockStride.width >> blockStride.height; CV_Assert(!blockStride.empty());\n    it = obj[\"cellSize\"].begin();\n    it >> cellSize.width >> cellSize.height; CV_Assert(!cellSize.empty());\n    obj[\"nbins\"] >> nbins; CV_Assert(nbins > 0);\n    obj[\"derivAperture\"] >> derivAperture;\n    obj[\"winSigma\"] >> winSigma;\n    obj[\"histogramNormType\"] >> histogramNormType;\n    obj[\"L2HysThreshold\"] >> L2HysThreshold;\n    obj[\"gammaCorrection\"] >> gammaCorrection;\n    obj[\"nlevels\"] >> nlevels; CV_Assert(nlevels > 0);\n    if (obj[\"signedGradient\"].empty())\n        signedGradient = false;\n    else\n        obj[\"signedGradient\"] >> signedGradient;\n\n    FileNode vecNode = obj[\"SVMDetector\"];\n    if( vecNode.isSeq() )\n    {\n        std::vector<float> _svmDetector;\n        vecNode >> _svmDetector;\n        setSVMDetector(_svmDetector);\n    }\n    return true;\n}",
            "func_before": "bool HOGDescriptor::read(FileNode& obj)\n{\n    CV_Assert(!obj[\"winSize\"].empty());\n\n    if( !obj.isMap() )\n        return false;\n    FileNodeIterator it = obj[\"winSize\"].begin();\n    it >> winSize.width >> winSize.height;\n    it = obj[\"blockSize\"].begin();\n    it >> blockSize.width >> blockSize.height;\n    it = obj[\"blockStride\"].begin();\n    it >> blockStride.width >> blockStride.height;\n    it = obj[\"cellSize\"].begin();\n    it >> cellSize.width >> cellSize.height;\n    obj[\"nbins\"] >> nbins;\n    obj[\"derivAperture\"] >> derivAperture;\n    obj[\"winSigma\"] >> winSigma;\n    obj[\"histogramNormType\"] >> histogramNormType;\n    obj[\"L2HysThreshold\"] >> L2HysThreshold;\n    obj[\"gammaCorrection\"] >> gammaCorrection;\n    obj[\"nlevels\"] >> nlevels;\n    if (obj[\"signedGradient\"].empty())\n        signedGradient = false;\n    else\n        obj[\"signedGradient\"] >> signedGradient;\n\n    FileNode vecNode = obj[\"SVMDetector\"];\n    if( vecNode.isSeq() )\n    {\n        std::vector<float> _svmDetector;\n        vecNode >> _svmDetector;\n        setSVMDetector(_svmDetector);\n    }\n    return true;\n}",
        },
        {
            "func": "Status OpLevelCostEstimator::PredictMaxPoolGrad(const OpContext& op_context,\n                                                NodeCosts* node_costs) const {\n  bool found_unknown_shapes = false;\n  const auto& op_info = op_context.op_info;\n  // x: op_info.inputs(0)\n  // y: op_info.inputs(1)\n  // y_grad: op_info.inputs(2)\n  if (op_info.inputs_size() < 3) {\n    return errors::InvalidArgument(\"MaxPoolGrad op has invalid inputs: \",\n                                   op_info.ShortDebugString());\n  }\n\n  TF_ASSIGN_OR_RETURN(ConvolutionDimensions dims,\n                      OpDimensionsFromInputs(op_info.inputs(0).shape(), op_info,\n                                             &found_unknown_shapes));\n\n  int64_t ops = 0;\n  if (dims.kx == 1 && dims.ky == 1) {\n    // 1x1 window. No need to know which input was max.\n    ops = dims.batch * dims.ix * dims.iy * dims.iz;\n  } else if (dims.kx <= dims.sx && dims.ky <= dims.sy) {\n    // Non-overlapping window: re-run maxpool, then assign zero or y_grad.\n    ops = dims.batch * dims.iz *\n          (dims.ox * dims.oy * (dims.kx * dims.ky - 1) + dims.ix * dims.iy);\n  } else {\n    // Overlapping window: initialize with zeros, re-run maxpool, then\n    // accumulate y_gad to proper x_grad locations.\n    ops = dims.batch * dims.iz *\n          (dims.ox * dims.oy * (dims.kx * dims.ky - 1) + dims.ix * dims.iy * 2);\n  }\n  node_costs->num_compute_ops = ops;\n\n  // Just read x and y_grad; no need to read y as we assume MaxPoolGrad re-run\n  // MaxPool internally.\n  const int64_t input0_size =\n      CalculateTensorSize(op_info.inputs(0), &found_unknown_shapes);\n  const int64_t input2_size =\n      CalculateTensorSize(op_info.inputs(2), &found_unknown_shapes);\n  node_costs->num_input_bytes_accessed = {input0_size, 0, input2_size};\n  // Write x_grad; size equal to x.\n  const int64_t output_size =\n      CalculateTensorSize(op_info.inputs(0), &found_unknown_shapes);\n  node_costs->num_output_bytes_accessed = {output_size};\n  node_costs->max_memory = output_size;\n\n  if (found_unknown_shapes) {\n    node_costs->inaccurate = true;\n    node_costs->num_nodes_with_unknown_shapes = 1;\n  }\n  return Status::OK();\n}",
            "func_before": "Status OpLevelCostEstimator::PredictMaxPoolGrad(const OpContext& op_context,\n                                                NodeCosts* node_costs) const {\n  bool found_unknown_shapes = false;\n  const auto& op_info = op_context.op_info;\n  // x: op_info.inputs(0)\n  // y: op_info.inputs(1)\n  // y_grad: op_info.inputs(2)\n  if (op_info.inputs_size() < 3) {\n    return errors::InvalidArgument(\"MaxPoolGrad op has invalid inputs: \",\n                                   op_info.ShortDebugString());\n  }\n\n  ConvolutionDimensions dims = OpDimensionsFromInputs(\n      op_info.inputs(0).shape(), op_info, &found_unknown_shapes);\n\n  int64_t ops = 0;\n  if (dims.kx == 1 && dims.ky == 1) {\n    // 1x1 window. No need to know which input was max.\n    ops = dims.batch * dims.ix * dims.iy * dims.iz;\n  } else if (dims.kx <= dims.sx && dims.ky <= dims.sy) {\n    // Non-overlapping window: re-run maxpool, then assign zero or y_grad.\n    ops = dims.batch * dims.iz *\n          (dims.ox * dims.oy * (dims.kx * dims.ky - 1) + dims.ix * dims.iy);\n  } else {\n    // Overlapping window: initialize with zeros, re-run maxpool, then\n    // accumulate y_gad to proper x_grad locations.\n    ops = dims.batch * dims.iz *\n          (dims.ox * dims.oy * (dims.kx * dims.ky - 1) + dims.ix * dims.iy * 2);\n  }\n  node_costs->num_compute_ops = ops;\n\n  // Just read x and y_grad; no need to read y as we assume MaxPoolGrad re-run\n  // MaxPool internally.\n  const int64_t input0_size =\n      CalculateTensorSize(op_info.inputs(0), &found_unknown_shapes);\n  const int64_t input2_size =\n      CalculateTensorSize(op_info.inputs(2), &found_unknown_shapes);\n  node_costs->num_input_bytes_accessed = {input0_size, 0, input2_size};\n  // Write x_grad; size equal to x.\n  const int64_t output_size =\n      CalculateTensorSize(op_info.inputs(0), &found_unknown_shapes);\n  node_costs->num_output_bytes_accessed = {output_size};\n  node_costs->max_memory = output_size;\n\n  if (found_unknown_shapes) {\n    node_costs->inaccurate = true;\n    node_costs->num_nodes_with_unknown_shapes = 1;\n  }\n  return Status::OK();\n}",
        }
    ],
    'check memory access error': [
        {
            "func": "static int legacy_parse_param(struct fs_context *fc, struct fs_parameter *param)\n{\n\tstruct legacy_fs_context *ctx = fc->fs_private;\n\tunsigned int size = ctx->data_size;\n\tsize_t len = 0;\n\tint ret;\n\n\tret = vfs_parse_fs_param_source(fc, param);\n\tif (ret != -ENOPARAM)\n\t\treturn ret;\n\n\tif (ctx->param_type == LEGACY_FS_MONOLITHIC_PARAMS)\n\t\treturn invalf(fc, \"VFS: Legacy: Can't mix monolithic and individual options\");\n\n\tswitch (param->type) {\n\tcase fs_value_is_string:\n\t\tlen = 1 + param->size;\n\t\tfallthrough;\n\tcase fs_value_is_flag:\n\t\tlen += strlen(param->key);\n\t\tbreak;\n\tdefault:\n\t\treturn invalf(fc, \"VFS: Legacy: Parameter type for '%s' not supported\",\n\t\t\t      param->key);\n\t}\n\n\tif (size + len + 2 > PAGE_SIZE)\n\t\treturn invalf(fc, \"VFS: Legacy: Cumulative options too large\");\n\tif (strchr(param->key, ',') ||\n\t    (param->type == fs_value_is_string &&\n\t     memchr(param->string, ',', param->size)))\n\t\treturn invalf(fc, \"VFS: Legacy: Option '%s' contained comma\",\n\t\t\t      param->key);\n\tif (!ctx->legacy_data) {\n\t\tctx->legacy_data = kmalloc(PAGE_SIZE, GFP_KERNEL);\n\t\tif (!ctx->legacy_data)\n\t\t\treturn -ENOMEM;\n\t}\n\n\tctx->legacy_data[size++] = ',';\n\tlen = strlen(param->key);\n\tmemcpy(ctx->legacy_data + size, param->key, len);\n\tsize += len;\n\tif (param->type == fs_value_is_string) {\n\t\tctx->legacy_data[size++] = '=';\n\t\tmemcpy(ctx->legacy_data + size, param->string, param->size);\n\t\tsize += param->size;\n\t}\n\tctx->legacy_data[size] = '\\0';\n\tctx->data_size = size;\n\tctx->param_type = LEGACY_FS_INDIVIDUAL_PARAMS;\n\treturn 0;\n}",
            "func_before": "static int legacy_parse_param(struct fs_context *fc, struct fs_parameter *param)\n{\n\tstruct legacy_fs_context *ctx = fc->fs_private;\n\tunsigned int size = ctx->data_size;\n\tsize_t len = 0;\n\tint ret;\n\n\tret = vfs_parse_fs_param_source(fc, param);\n\tif (ret != -ENOPARAM)\n\t\treturn ret;\n\n\tif (ctx->param_type == LEGACY_FS_MONOLITHIC_PARAMS)\n\t\treturn invalf(fc, \"VFS: Legacy: Can't mix monolithic and individual options\");\n\n\tswitch (param->type) {\n\tcase fs_value_is_string:\n\t\tlen = 1 + param->size;\n\t\tfallthrough;\n\tcase fs_value_is_flag:\n\t\tlen += strlen(param->key);\n\t\tbreak;\n\tdefault:\n\t\treturn invalf(fc, \"VFS: Legacy: Parameter type for '%s' not supported\",\n\t\t\t      param->key);\n\t}\n\n\tif (len > PAGE_SIZE - 2 - size)\n\t\treturn invalf(fc, \"VFS: Legacy: Cumulative options too large\");\n\tif (strchr(param->key, ',') ||\n\t    (param->type == fs_value_is_string &&\n\t     memchr(param->string, ',', param->size)))\n\t\treturn invalf(fc, \"VFS: Legacy: Option '%s' contained comma\",\n\t\t\t      param->key);\n\tif (!ctx->legacy_data) {\n\t\tctx->legacy_data = kmalloc(PAGE_SIZE, GFP_KERNEL);\n\t\tif (!ctx->legacy_data)\n\t\t\treturn -ENOMEM;\n\t}\n\n\tctx->legacy_data[size++] = ',';\n\tlen = strlen(param->key);\n\tmemcpy(ctx->legacy_data + size, param->key, len);\n\tsize += len;\n\tif (param->type == fs_value_is_string) {\n\t\tctx->legacy_data[size++] = '=';\n\t\tmemcpy(ctx->legacy_data + size, param->string, param->size);\n\t\tsize += param->size;\n\t}\n\tctx->legacy_data[size] = '\\0';\n\tctx->data_size = size;\n\tctx->param_type = LEGACY_FS_INDIVIDUAL_PARAMS;\n\treturn 0;\n}",
        },
        {
            "func": "const char *luaG_findlocal (lua_State *L, CallInfo *ci, int n, StkId *pos) {\n  StkId base = ci->func + 1;\n  const char *name = NULL;\n  if (isLua(ci)) {\n    if (n < 0)  /* access to vararg values? */\n      return findvararg(ci, n, pos);\n    else\n      name = luaF_getlocalname(ci_func(ci)->p, n, currentpc(ci));\n  }\n  if (name == NULL) {  /* no 'standard' name? */\n    StkId limit = (ci == L->ci) ? L->top : ci->next->func;\n    if (limit - base >= n && n > 0) {  /* is 'n' inside 'ci' stack? */\n      /* generic name for any valid slot */\n      name = isLua(ci) ? \"(temporary)\" : \"(C temporary)\";\n    }\n    else\n      return NULL;  /* no name */\n  }\n  if (pos)\n    *pos = base + (n - 1);\n  return name;\n}",
            "func_before": "const char *luaG_findlocal (lua_State *L, CallInfo *ci, int n, StkId *pos) {\n  StkId base = ci->func + 1;\n  const char *name = NULL;\n  if (isLua(ci)) {\n    if (n < 0)  /* access to vararg values? */\n      return findvararg(ci, -n, pos);\n    else\n      name = luaF_getlocalname(ci_func(ci)->p, n, currentpc(ci));\n  }\n  if (name == NULL) {  /* no 'standard' name? */\n    StkId limit = (ci == L->ci) ? L->top : ci->next->func;\n    if (limit - base >= n && n > 0) {  /* is 'n' inside 'ci' stack? */\n      /* generic name for any valid slot */\n      name = isLua(ci) ? \"(temporary)\" : \"(C temporary)\";\n    }\n    else\n      return NULL;  /* no name */\n  }\n  if (pos)\n    *pos = base + (n - 1);\n  return name;\n}",
        },
        {
            "func": "static inline LineContribType * _gdContributionsAlloc(unsigned int line_length, unsigned int windows_size)\n{\n\tunsigned int u = 0;\n\tLineContribType *res;\n\tsize_t weights_size;\n\n\tif (overflow2(windows_size, sizeof(double))) {\n\t\treturn NULL;\n\t} else {\n\t\tweights_size = windows_size * sizeof(double);\n\t}\n\tres = (LineContribType *) gdMalloc(sizeof(LineContribType));\n\tif (!res) {\n\t\treturn NULL;\n\t}\n\tres->WindowSize = windows_size;\n\tres->LineLength = line_length;\n\tif (overflow2(line_length, sizeof(ContributionType))) {\n\t\tgdFree(res);\n\t\treturn NULL;\n\t}\n\tres->ContribRow = (ContributionType *) gdMalloc(line_length * sizeof(ContributionType));\n\tif (res->ContribRow == NULL) {\n\t\tgdFree(res);\n\t\treturn NULL;\n\t}\n\tfor (u = 0 ; u < line_length ; u++) {\n\t\tres->ContribRow[u].Weights = (double *) gdMalloc(weights_size);\n\t\tif (res->ContribRow[u].Weights == NULL) {\n\t\t\tunsigned int i;\n\n\t\t\tfor (i=0;i<u;i++) {\n\t\t\t\tgdFree(res->ContribRow[i].Weights);\n\t\t\t}\n\t\t\tgdFree(res->ContribRow);\n\t\t\tgdFree(res);\n\t\t\treturn NULL;\n\t\t}\n\t}\n\treturn res;\n}",
            "func_before": "static inline LineContribType * _gdContributionsAlloc(unsigned int line_length, unsigned int windows_size)\n{\n\tunsigned int u = 0;\n\tLineContribType *res;\n\tint overflow_error = 0;\n\n\tres = (LineContribType *) gdMalloc(sizeof(LineContribType));\n\tif (!res) {\n\t\treturn NULL;\n\t}\n\tres->WindowSize = windows_size;\n\tres->LineLength = line_length;\n\tif (overflow2(line_length, sizeof(ContributionType))) {\n\t\tgdFree(res);\n\t\treturn NULL;\n\t}\n\tres->ContribRow = (ContributionType *) gdMalloc(line_length * sizeof(ContributionType));\n\tif (res->ContribRow == NULL) {\n\t\tgdFree(res);\n\t\treturn NULL;\n\t}\n\tfor (u = 0 ; u < line_length ; u++) {\n\t\tif (overflow2(windows_size, sizeof(double))) {\n\t\t\toverflow_error = 1;\n\t\t} else {\n\t\t\tres->ContribRow[u].Weights = (double *) gdMalloc(windows_size * sizeof(double));\n\t\t}\n\t\tif (overflow_error == 1 || res->ContribRow[u].Weights == NULL) {\n\t\t\tunsigned int i;\n\t\t\tu--;\n\t\t\tfor (i=0;i<=u;i++) {\n\t\t\t\tgdFree(res->ContribRow[i].Weights);\n\t\t\t}\n\t\t\tgdFree(res->ContribRow);\n\t\t\tgdFree(res);\n\t\t\treturn NULL;\n\t\t}\n\t}\n\treturn res;\n}",
        }
    ],
    'assertion error': [
        {
            "func": "static bfd_boolean\nihex_read_section (bfd *abfd, asection *section, bfd_byte *contents)\n{\n  int c;\n  bfd_byte *p;\n  bfd_byte *buf = NULL;\n  size_t bufsize;\n  bfd_boolean error;\n\n  if (bfd_seek (abfd, section->filepos, SEEK_SET) != 0)\n    goto error_return;\n\n  p = contents;\n  bufsize = 0;\n  error = FALSE;\n  while ((c = ihex_get_byte (abfd, &error)) != EOF)\n    {\n      unsigned char hdr[8];\n      unsigned int len;\n      unsigned int type;\n      unsigned int i;\n\n      if (c == '\\r' || c == '\\n')\n\tcontinue;\n\n      /* This is called after ihex_scan has succeeded, so we ought to\n         know the exact format.  */\n      BFD_ASSERT (c == ':');\n\n      if (bfd_bread (hdr, (bfd_size_type) 8, abfd) != 8)\n\tgoto error_return;\n\n      len = HEX2 (hdr);\n      type = HEX2 (hdr + 6);\n\n      /* We should only see type 0 records here.  */\n      if (type != 0)\n\t{\n\t  (*_bfd_error_handler)\n\t    (_(\"%B: internal error in ihex_read_section\"), abfd);\n\t  bfd_set_error (bfd_error_bad_value);\n\t  goto error_return;\n\t}\n\n      if (len * 2 > bufsize)\n\t{\n\t  buf = (bfd_byte *) bfd_realloc (buf, (bfd_size_type) len * 2);\n\t  if (buf == NULL)\n\t    goto error_return;\n\t  bufsize = len * 2;\n\t}\n\n      if (bfd_bread (buf, (bfd_size_type) len * 2, abfd) != len * 2)\n\tgoto error_return;\n\n      for (i = 0; i < len; i++)\n\t*p++ = HEX2 (buf + 2 * i);\n      if ((bfd_size_type) (p - contents) >= section->size)\n\t{\n\t  /* We've read everything in the section.  */\n\t  if (buf != NULL)\n\t    free (buf);\n\t  return TRUE;\n\t}\n\n      /* Skip the checksum.  */\n      if (bfd_bread (buf, (bfd_size_type) 2, abfd) != 2)\n\tgoto error_return;\n    }\n\n  if ((bfd_size_type) (p - contents) < section->size)\n    {\n      (*_bfd_error_handler)\n\t(_(\"%B: bad section length in ihex_read_section\"), abfd);\n      bfd_set_error (bfd_error_bad_value);\n      goto error_return;\n    }\n\n  if (buf != NULL)\n    free (buf);\n\n  return TRUE;\n\n error_return:\n  if (buf != NULL)\n    free (buf);\n  return FALSE;\n}",
            "func_before": "static bfd_boolean\nihex_read_section (bfd *abfd, asection *section, bfd_byte *contents)\n{\n  int c;\n  bfd_byte *p;\n  bfd_byte *buf = NULL;\n  size_t bufsize;\n  bfd_boolean error;\n\n  if (bfd_seek (abfd, section->filepos, SEEK_SET) != 0)\n    goto error_return;\n\n  p = contents;\n  bufsize = 0;\n  error = FALSE;\n  while ((c = ihex_get_byte (abfd, &error)) != EOF)\n    {\n      char hdr[8];\n      unsigned int len;\n      unsigned int type;\n      unsigned int i;\n\n      if (c == '\\r' || c == '\\n')\n\tcontinue;\n\n      /* This is called after ihex_scan has succeeded, so we ought to\n         know the exact format.  */\n      BFD_ASSERT (c == ':');\n\n      if (bfd_bread (hdr, (bfd_size_type) 8, abfd) != 8)\n\tgoto error_return;\n\n      len = HEX2 (hdr);\n      type = HEX2 (hdr + 6);\n\n      /* We should only see type 0 records here.  */\n      if (type != 0)\n\t{\n\t  (*_bfd_error_handler)\n\t    (_(\"%B: internal error in ihex_read_section\"), abfd);\n\t  bfd_set_error (bfd_error_bad_value);\n\t  goto error_return;\n\t}\n\n      if (len * 2 > bufsize)\n\t{\n\t  buf = (bfd_byte *) bfd_realloc (buf, (bfd_size_type) len * 2);\n\t  if (buf == NULL)\n\t    goto error_return;\n\t  bufsize = len * 2;\n\t}\n\n      if (bfd_bread (buf, (bfd_size_type) len * 2, abfd) != len * 2)\n\tgoto error_return;\n\n      for (i = 0; i < len; i++)\n\t*p++ = HEX2 (buf + 2 * i);\n      if ((bfd_size_type) (p - contents) >= section->size)\n\t{\n\t  /* We've read everything in the section.  */\n\t  if (buf != NULL)\n\t    free (buf);\n\t  return TRUE;\n\t}\n\n      /* Skip the checksum.  */\n      if (bfd_bread (buf, (bfd_size_type) 2, abfd) != 2)\n\tgoto error_return;\n    }\n\n  if ((bfd_size_type) (p - contents) < section->size)\n    {\n      (*_bfd_error_handler)\n\t(_(\"%B: bad section length in ihex_read_section\"), abfd);\n      bfd_set_error (bfd_error_bad_value);\n      goto error_return;\n    }\n\n  if (buf != NULL)\n    free (buf);\n\n  return TRUE;\n\n error_return:\n  if (buf != NULL)\n    free (buf);\n  return FALSE;\n}",
        },
        {
            "func": "static void jsR_calllwfunction(js_State *J, int n, js_Function *F, js_Environment *scope)\n{\n\tjs_Value v;\n\tint i;\n\n\tjsR_savescope(J, scope);\n\n\tif (n > F->numparams) {\n\t\tjs_pop(J, n - F->numparams);\n\t\tn = F->numparams;\n\t}\n\tfor (i = n; i < F->varlen; ++i)\n\t\tjs_pushundefined(J);\n\n\tjsR_run(J, F);\n\tv = *stackidx(J, -1);\n\tTOP = --BOT; /* clear stack */\n\tjs_pushvalue(J, v);\n\n\tjsR_restorescope(J);\n}",
            "func_before": "static void jsR_calllwfunction(js_State *J, int n, js_Function *F, js_Environment *scope)\n{\n\tjs_Value v;\n\tint i;\n\n\tjsR_savescope(J, scope);\n\n\tif (n > F->numparams) {\n\t\tjs_pop(J, F->numparams - n);\n\t\tn = F->numparams;\n\t}\n\tfor (i = n; i < F->varlen; ++i)\n\t\tjs_pushundefined(J);\n\n\tjsR_run(J, F);\n\tv = *stackidx(J, -1);\n\tTOP = --BOT; /* clear stack */\n\tjs_pushvalue(J, v);\n\n\tjsR_restorescope(J);\n}",
        },
        {
            "func": "static int readContigStripsIntoBuffer (TIFF* in, uint8* buf)\n{\n        uint8* bufp = buf;\n        int32  bytes_read = 0;\n        uint32 strip, nstrips   = TIFFNumberOfStrips(in);\n        uint32 stripsize = TIFFStripSize(in);\n        uint32 rows = 0;\n        uint32 rps = TIFFGetFieldDefaulted(in, TIFFTAG_ROWSPERSTRIP, &rps);\n        tsize_t scanline_size = TIFFScanlineSize(in);\n\n        if (scanline_size == 0) {\n                TIFFError(\"\", \"TIFF scanline size is zero!\");    \n                return 0;\n        }\n\n        for (strip = 0; strip < nstrips; strip++) {\n                bytes_read = TIFFReadEncodedStrip (in, strip, bufp, -1);\n                rows = bytes_read / scanline_size;\n                if ((strip < (nstrips - 1)) && (bytes_read != (int32)stripsize))\n                        TIFFError(\"\", \"Strip %d: read %lu bytes, strip size %lu\",\n                                  (int)strip + 1, (unsigned long) bytes_read,\n                                  (unsigned long)stripsize);\n\n                if (bytes_read < 0 && !ignore) {\n                        TIFFError(\"\", \"Error reading strip %lu after %lu rows\",\n                                  (unsigned long) strip, (unsigned long)rows);\n                        return 0;\n                }\n                bufp += stripsize;\n        }\n\n        return 1;\n}",
            "func_before": "static int readContigStripsIntoBuffer (TIFF* in, uint8* buf)\n{\n        uint8* bufp = buf;\n        int32  bytes_read = 0;\n        uint32 strip, nstrips   = TIFFNumberOfStrips(in);\n        uint32 stripsize = TIFFStripSize(in);\n        uint32 rows = 0;\n        uint32 rps = TIFFGetFieldDefaulted(in, TIFFTAG_ROWSPERSTRIP, &rps);\n        tsize_t scanline_size = TIFFScanlineSize(in);\n\n        if (scanline_size == 0) {\n                TIFFError(\"\", \"TIFF scanline size is zero!\");    \n                return 0;\n        }\n\n        for (strip = 0; strip < nstrips; strip++) {\n                bytes_read = TIFFReadEncodedStrip (in, strip, bufp, -1);\n                rows = bytes_read / scanline_size;\n                if ((strip < (nstrips - 1)) && (bytes_read != (int32)stripsize))\n                        TIFFError(\"\", \"Strip %d: read %lu bytes, strip size %lu\",\n                                  (int)strip + 1, (unsigned long) bytes_read,\n                                  (unsigned long)stripsize);\n\n                if (bytes_read < 0 && !ignore) {\n                        TIFFError(\"\", \"Error reading strip %lu after %lu rows\",\n                                  (unsigned long) strip, (unsigned long)rows);\n                        return 0;\n                }\n                bufp += bytes_read;\n        }\n\n        return 1;\n}",
        }
    ],
    'memcpy error': [
        {
            "func": "static bfd_boolean\nihex_read_section (bfd *abfd, asection *section, bfd_byte *contents)\n{\n  int c;\n  bfd_byte *p;\n  bfd_byte *buf = NULL;\n  size_t bufsize;\n  bfd_boolean error;\n\n  if (bfd_seek (abfd, section->filepos, SEEK_SET) != 0)\n    goto error_return;\n\n  p = contents;\n  bufsize = 0;\n  error = FALSE;\n  while ((c = ihex_get_byte (abfd, &error)) != EOF)\n    {\n      unsigned char hdr[8];\n      unsigned int len;\n      unsigned int type;\n      unsigned int i;\n\n      if (c == '\\r' || c == '\\n')\n\tcontinue;\n\n      /* This is called after ihex_scan has succeeded, so we ought to\n         know the exact format.  */\n      BFD_ASSERT (c == ':');\n\n      if (bfd_bread (hdr, (bfd_size_type) 8, abfd) != 8)\n\tgoto error_return;\n\n      len = HEX2 (hdr);\n      type = HEX2 (hdr + 6);\n\n      /* We should only see type 0 records here.  */\n      if (type != 0)\n\t{\n\t  (*_bfd_error_handler)\n\t    (_(\"%B: internal error in ihex_read_section\"), abfd);\n\t  bfd_set_error (bfd_error_bad_value);\n\t  goto error_return;\n\t}\n\n      if (len * 2 > bufsize)\n\t{\n\t  buf = (bfd_byte *) bfd_realloc (buf, (bfd_size_type) len * 2);\n\t  if (buf == NULL)\n\t    goto error_return;\n\t  bufsize = len * 2;\n\t}\n\n      if (bfd_bread (buf, (bfd_size_type) len * 2, abfd) != len * 2)\n\tgoto error_return;\n\n      for (i = 0; i < len; i++)\n\t*p++ = HEX2 (buf + 2 * i);\n      if ((bfd_size_type) (p - contents) >= section->size)\n\t{\n\t  /* We've read everything in the section.  */\n\t  if (buf != NULL)\n\t    free (buf);\n\t  return TRUE;\n\t}\n\n      /* Skip the checksum.  */\n      if (bfd_bread (buf, (bfd_size_type) 2, abfd) != 2)\n\tgoto error_return;\n    }\n\n  if ((bfd_size_type) (p - contents) < section->size)\n    {\n      (*_bfd_error_handler)\n\t(_(\"%B: bad section length in ihex_read_section\"), abfd);\n      bfd_set_error (bfd_error_bad_value);\n      goto error_return;\n    }\n\n  if (buf != NULL)\n    free (buf);\n\n  return TRUE;\n\n error_return:\n  if (buf != NULL)\n    free (buf);\n  return FALSE;\n}",
            "func_before": "static bfd_boolean\nihex_read_section (bfd *abfd, asection *section, bfd_byte *contents)\n{\n  int c;\n  bfd_byte *p;\n  bfd_byte *buf = NULL;\n  size_t bufsize;\n  bfd_boolean error;\n\n  if (bfd_seek (abfd, section->filepos, SEEK_SET) != 0)\n    goto error_return;\n\n  p = contents;\n  bufsize = 0;\n  error = FALSE;\n  while ((c = ihex_get_byte (abfd, &error)) != EOF)\n    {\n      char hdr[8];\n      unsigned int len;\n      unsigned int type;\n      unsigned int i;\n\n      if (c == '\\r' || c == '\\n')\n\tcontinue;\n\n      /* This is called after ihex_scan has succeeded, so we ought to\n         know the exact format.  */\n      BFD_ASSERT (c == ':');\n\n      if (bfd_bread (hdr, (bfd_size_type) 8, abfd) != 8)\n\tgoto error_return;\n\n      len = HEX2 (hdr);\n      type = HEX2 (hdr + 6);\n\n      /* We should only see type 0 records here.  */\n      if (type != 0)\n\t{\n\t  (*_bfd_error_handler)\n\t    (_(\"%B: internal error in ihex_read_section\"), abfd);\n\t  bfd_set_error (bfd_error_bad_value);\n\t  goto error_return;\n\t}\n\n      if (len * 2 > bufsize)\n\t{\n\t  buf = (bfd_byte *) bfd_realloc (buf, (bfd_size_type) len * 2);\n\t  if (buf == NULL)\n\t    goto error_return;\n\t  bufsize = len * 2;\n\t}\n\n      if (bfd_bread (buf, (bfd_size_type) len * 2, abfd) != len * 2)\n\tgoto error_return;\n\n      for (i = 0; i < len; i++)\n\t*p++ = HEX2 (buf + 2 * i);\n      if ((bfd_size_type) (p - contents) >= section->size)\n\t{\n\t  /* We've read everything in the section.  */\n\t  if (buf != NULL)\n\t    free (buf);\n\t  return TRUE;\n\t}\n\n      /* Skip the checksum.  */\n      if (bfd_bread (buf, (bfd_size_type) 2, abfd) != 2)\n\tgoto error_return;\n    }\n\n  if ((bfd_size_type) (p - contents) < section->size)\n    {\n      (*_bfd_error_handler)\n\t(_(\"%B: bad section length in ihex_read_section\"), abfd);\n      bfd_set_error (bfd_error_bad_value);\n      goto error_return;\n    }\n\n  if (buf != NULL)\n    free (buf);\n\n  return TRUE;\n\n error_return:\n  if (buf != NULL)\n    free (buf);\n  return FALSE;\n}",
        },
        {
            "func": "static void jsR_calllwfunction(js_State *J, int n, js_Function *F, js_Environment *scope)\n{\n\tjs_Value v;\n\tint i;\n\n\tjsR_savescope(J, scope);\n\n\tif (n > F->numparams) {\n\t\tjs_pop(J, n - F->numparams);\n\t\tn = F->numparams;\n\t}\n\tfor (i = n; i < F->varlen; ++i)\n\t\tjs_pushundefined(J);\n\n\tjsR_run(J, F);\n\tv = *stackidx(J, -1);\n\tTOP = --BOT; /* clear stack */\n\tjs_pushvalue(J, v);\n\n\tjsR_restorescope(J);\n}",
            "func_before": "static void jsR_calllwfunction(js_State *J, int n, js_Function *F, js_Environment *scope)\n{\n\tjs_Value v;\n\tint i;\n\n\tjsR_savescope(J, scope);\n\n\tif (n > F->numparams) {\n\t\tjs_pop(J, F->numparams - n);\n\t\tn = F->numparams;\n\t}\n\tfor (i = n; i < F->varlen; ++i)\n\t\tjs_pushundefined(J);\n\n\tjsR_run(J, F);\n\tv = *stackidx(J, -1);\n\tTOP = --BOT; /* clear stack */\n\tjs_pushvalue(J, v);\n\n\tjsR_restorescope(J);\n}",
        },
        {
            "func": "static int readContigStripsIntoBuffer (TIFF* in, uint8* buf)\n{\n        uint8* bufp = buf;\n        int32  bytes_read = 0;\n        uint32 strip, nstrips   = TIFFNumberOfStrips(in);\n        uint32 stripsize = TIFFStripSize(in);\n        uint32 rows = 0;\n        uint32 rps = TIFFGetFieldDefaulted(in, TIFFTAG_ROWSPERSTRIP, &rps);\n        tsize_t scanline_size = TIFFScanlineSize(in);\n\n        if (scanline_size == 0) {\n                TIFFError(\"\", \"TIFF scanline size is zero!\");    \n                return 0;\n        }\n\n        for (strip = 0; strip < nstrips; strip++) {\n                bytes_read = TIFFReadEncodedStrip (in, strip, bufp, -1);\n                rows = bytes_read / scanline_size;\n                if ((strip < (nstrips - 1)) && (bytes_read != (int32)stripsize))\n                        TIFFError(\"\", \"Strip %d: read %lu bytes, strip size %lu\",\n                                  (int)strip + 1, (unsigned long) bytes_read,\n                                  (unsigned long)stripsize);\n\n                if (bytes_read < 0 && !ignore) {\n                        TIFFError(\"\", \"Error reading strip %lu after %lu rows\",\n                                  (unsigned long) strip, (unsigned long)rows);\n                        return 0;\n                }\n                bufp += stripsize;\n        }\n\n        return 1;\n}",
            "func_before": "static int readContigStripsIntoBuffer (TIFF* in, uint8* buf)\n{\n        uint8* bufp = buf;\n        int32  bytes_read = 0;\n        uint32 strip, nstrips   = TIFFNumberOfStrips(in);\n        uint32 stripsize = TIFFStripSize(in);\n        uint32 rows = 0;\n        uint32 rps = TIFFGetFieldDefaulted(in, TIFFTAG_ROWSPERSTRIP, &rps);\n        tsize_t scanline_size = TIFFScanlineSize(in);\n\n        if (scanline_size == 0) {\n                TIFFError(\"\", \"TIFF scanline size is zero!\");    \n                return 0;\n        }\n\n        for (strip = 0; strip < nstrips; strip++) {\n                bytes_read = TIFFReadEncodedStrip (in, strip, bufp, -1);\n                rows = bytes_read / scanline_size;\n                if ((strip < (nstrips - 1)) && (bytes_read != (int32)stripsize))\n                        TIFFError(\"\", \"Strip %d: read %lu bytes, strip size %lu\",\n                                  (int)strip + 1, (unsigned long) bytes_read,\n                                  (unsigned long)stripsize);\n\n                if (bytes_read < 0 && !ignore) {\n                        TIFFError(\"\", \"Error reading strip %lu after %lu rows\",\n                                  (unsigned long) strip, (unsigned long)rows);\n                        return 0;\n                }\n                bufp += bytes_read;\n        }\n\n        return 1;\n}",
        }
    ],
    'overflow on shift operation': [
        {
            "func": "VALUE\nrb_dlhandle_initialize(int argc, VALUE argv[], VALUE self)\n{\n  void *ptr;\n  struct dl_handle *dlhandle;\n  VALUE lib, flag;\n  char  *clib;\n  int   cflag;\n  const char *err;\n\n  switch( rb_scan_args(argc, argv, \"02\", &lib, &flag) ){\n  case 0:\n    clib = NULL;\n    cflag = RTLD_LAZY | RTLD_GLOBAL;\n    break;\n  case 1:\n    clib = NIL_P(lib) ? NULL : SafeStringValuePtr(lib);\n    cflag = RTLD_LAZY | RTLD_GLOBAL;\n    break;\n  case 2:\n    clib = NIL_P(lib) ? NULL : SafeStringValuePtr(lib);\n    cflag = NUM2INT(flag);\n    break;\n  default:\n    rb_bug(\"rb_dlhandle_new\");\n  }\n\n  ptr = dlopen(clib, cflag);\n#if defined(HAVE_DLERROR)\n  if( !ptr && (err = dlerror()) ){\n    rb_raise(rb_eDLError, \"%s\", err);\n  }\n#else\n  if( !ptr ){\n    err = dlerror();\n    rb_raise(rb_eDLError, \"%s\", err);\n  }\n#endif\n  Data_Get_Struct(self, struct dl_handle, dlhandle);\n  if( dlhandle->ptr && dlhandle->open && dlhandle->enable_close ){\n    dlclose(dlhandle->ptr);\n  }\n  dlhandle->ptr = ptr;\n  dlhandle->open = 1;\n  dlhandle->enable_close = 0;\n\n  if( rb_block_given_p() ){\n    rb_ensure(rb_yield, self, rb_dlhandle_close, self);\n  }\n\n  return Qnil;\n}",
            "func_before": "VALUE\nrb_dlhandle_initialize(int argc, VALUE argv[], VALUE self)\n{\n  void *ptr;\n  struct dl_handle *dlhandle;\n  VALUE lib, flag;\n  char  *clib;\n  int   cflag;\n  const char *err;\n\n  switch( rb_scan_args(argc, argv, \"02\", &lib, &flag) ){\n  case 0:\n    clib = NULL;\n    cflag = RTLD_LAZY | RTLD_GLOBAL;\n    break;\n  case 1:\n    clib = NIL_P(lib) ? NULL : StringValuePtr(lib);\n    cflag = RTLD_LAZY | RTLD_GLOBAL;\n    break;\n  case 2:\n    clib = NIL_P(lib) ? NULL : StringValuePtr(lib);\n    cflag = NUM2INT(flag);\n    break;\n  default:\n    rb_bug(\"rb_dlhandle_new\");\n  }\n\n  ptr = dlopen(clib, cflag);\n#if defined(HAVE_DLERROR)\n  if( !ptr && (err = dlerror()) ){\n    rb_raise(rb_eDLError, \"%s\", err);\n  }\n#else\n  if( !ptr ){\n    err = dlerror();\n    rb_raise(rb_eDLError, \"%s\", err);\n  }\n#endif\n  Data_Get_Struct(self, struct dl_handle, dlhandle);\n  if( dlhandle->ptr && dlhandle->open && dlhandle->enable_close ){\n    dlclose(dlhandle->ptr);\n  }\n  dlhandle->ptr = ptr;\n  dlhandle->open = 1;\n  dlhandle->enable_close = 0;\n\n  if( rb_block_given_p() ){\n    rb_ensure(rb_yield, self, rb_dlhandle_close, self);\n  }\n\n  return Qnil;\n}",
        },
        {
            "func": "bool SSecurityPlain::processMsg(SConnection* sc)\n{\n  rdr::InStream* is = sc->getInStream();\n  char* pw;\n  char *uname;\n  CharArray password;\n\n  if (!valid)\n    throw AuthFailureException(\"No password validator configured\");\n\n  if (state == 0) {\n    if (!is->checkNoWait(8))\n      return false;\n    ulen = is->readU32();\n    plen = is->readU32();\n    state = 1;\n  }\n\n  if (state == 1) {\n    if (!is->checkNoWait(ulen + plen))\n      return false;\n    state = 2;\n    pw = new char[plen + 1];\n    uname = new char[ulen + 1];\n    username.replaceBuf(uname);\n    password.replaceBuf(pw);\n    is->readBytes(uname, ulen);\n    is->readBytes(pw, plen);\n    pw[plen] = 0;\n    uname[ulen] = 0;\n    plen = 0;\n    if (!valid->validate(sc, uname, pw))\n      throw AuthFailureException(\"invalid password or username\");\n  }\n\n  return true;\n}",
            "func_before": "bool SSecurityPlain::processMsg(SConnection* sc)\n{\n  rdr::InStream* is = sc->getInStream();\n  char* pw;\n  char *uname;\n  CharArray password;\n\n  if (!valid)\n    throw AuthFailureException(\"No password validator configured\");\n\n  if (state == 0) {\n    if (!is->checkNoWait(8))\n      return false;\n    ulen = is->readU32();\n    plen = is->readU32();\n    state = 1;\n  }\n\n  if (state == 1) {\n    if (is->checkNoWait(ulen + plen + 2))\n      return false;\n    state = 2;\n    pw = new char[plen + 1];\n    uname = new char[ulen + 1];\n    username.replaceBuf(uname);\n    password.replaceBuf(pw);\n    is->readBytes(uname, ulen);\n    is->readBytes(pw, plen);\n    pw[plen] = 0;\n    uname[ulen] = 0;\n    plen = 0;\n    if (!valid->validate(sc, uname, pw))\n      throw AuthFailureException(\"invalid password or username\");\n  }\n\n  return true;\n}",
        },
        {
            "func": "static MagickBooleanType SkipDXTMipmaps(Image *image,DDSInfo *dds_info,\n  int texel_size,ExceptionInfo *exception)\n{\n  register ssize_t\n    i;\n\n  MagickOffsetType\n    offset;\n\n  size_t\n    h,\n    w;\n\n  /*\n    Only skip mipmaps for textures and cube maps\n  */\n  if (EOFBlob(image) != MagickFalse)\n    {\n      ThrowFileException(exception,CorruptImageError,\"UnexpectedEndOfFile\",\n        image->filename);\n      return(MagickFalse);\n    }\n  if (dds_info->ddscaps1 & DDSCAPS_MIPMAP\n      && (dds_info->ddscaps1 & DDSCAPS_TEXTURE\n          || dds_info->ddscaps2 & DDSCAPS2_CUBEMAP))\n    {\n      w = DIV2(dds_info->width);\n      h = DIV2(dds_info->height);\n\n      /*\n        Mipmapcount includes the main image, so start from one\n      */\n      for (i = 1; (i < (ssize_t) dds_info->mipmapcount) && w && h; i++)\n      {\n        offset = (MagickOffsetType) ((w + 3) / 4) * ((h + 3) / 4) * texel_size;\n        (void) SeekBlob(image, offset, SEEK_CUR);\n\n        w = DIV2(w);\n        h = DIV2(h);\n      }\n    }\n  return(MagickTrue);\n}",
            "func_before": "static MagickBooleanType SkipDXTMipmaps(Image *image,DDSInfo *dds_info,\n  int texel_size,ExceptionInfo *exception)\n{\n  register ssize_t\n    i;\n\n  MagickOffsetType\n    offset;\n\n  size_t\n    h,\n    w;\n\n  /*\n    Only skip mipmaps for textures and cube maps\n  */\n  if (dds_info->ddscaps1 & DDSCAPS_MIPMAP\n      && (dds_info->ddscaps1 & DDSCAPS_TEXTURE\n          || dds_info->ddscaps2 & DDSCAPS2_CUBEMAP))\n    {\n      if (EOFBlob(image) != MagickFalse)\n        {\n          ThrowFileException(exception,CorruptImageError,\"UnexpectedEndOfFile\",\n            image->filename);\n          return(MagickFalse);\n        }\n      w = DIV2(dds_info->width);\n      h = DIV2(dds_info->height);\n\n      /*\n        Mipmapcount includes the main image, so start from one\n      */\n      for (i = 1; (i < (ssize_t) dds_info->mipmapcount) && w && h; i++)\n      {\n        offset = (MagickOffsetType) ((w + 3) / 4) * ((h + 3) / 4) * texel_size;\n        (void) SeekBlob(image, offset, SEEK_CUR);\n\n        w = DIV2(w);\n        h = DIV2(h);\n      }\n    }\n  return(MagickTrue);\n}",
        }
    ],
    'overflow on cast operation': [
        {
            "func": "VALUE\nrb_dlhandle_initialize(int argc, VALUE argv[], VALUE self)\n{\n  void *ptr;\n  struct dl_handle *dlhandle;\n  VALUE lib, flag;\n  char  *clib;\n  int   cflag;\n  const char *err;\n\n  switch( rb_scan_args(argc, argv, \"02\", &lib, &flag) ){\n  case 0:\n    clib = NULL;\n    cflag = RTLD_LAZY | RTLD_GLOBAL;\n    break;\n  case 1:\n    clib = NIL_P(lib) ? NULL : SafeStringValuePtr(lib);\n    cflag = RTLD_LAZY | RTLD_GLOBAL;\n    break;\n  case 2:\n    clib = NIL_P(lib) ? NULL : SafeStringValuePtr(lib);\n    cflag = NUM2INT(flag);\n    break;\n  default:\n    rb_bug(\"rb_dlhandle_new\");\n  }\n\n  ptr = dlopen(clib, cflag);\n#if defined(HAVE_DLERROR)\n  if( !ptr && (err = dlerror()) ){\n    rb_raise(rb_eDLError, \"%s\", err);\n  }\n#else\n  if( !ptr ){\n    err = dlerror();\n    rb_raise(rb_eDLError, \"%s\", err);\n  }\n#endif\n  Data_Get_Struct(self, struct dl_handle, dlhandle);\n  if( dlhandle->ptr && dlhandle->open && dlhandle->enable_close ){\n    dlclose(dlhandle->ptr);\n  }\n  dlhandle->ptr = ptr;\n  dlhandle->open = 1;\n  dlhandle->enable_close = 0;\n\n  if( rb_block_given_p() ){\n    rb_ensure(rb_yield, self, rb_dlhandle_close, self);\n  }\n\n  return Qnil;\n}",
            "func_before": "VALUE\nrb_dlhandle_initialize(int argc, VALUE argv[], VALUE self)\n{\n  void *ptr;\n  struct dl_handle *dlhandle;\n  VALUE lib, flag;\n  char  *clib;\n  int   cflag;\n  const char *err;\n\n  switch( rb_scan_args(argc, argv, \"02\", &lib, &flag) ){\n  case 0:\n    clib = NULL;\n    cflag = RTLD_LAZY | RTLD_GLOBAL;\n    break;\n  case 1:\n    clib = NIL_P(lib) ? NULL : StringValuePtr(lib);\n    cflag = RTLD_LAZY | RTLD_GLOBAL;\n    break;\n  case 2:\n    clib = NIL_P(lib) ? NULL : StringValuePtr(lib);\n    cflag = NUM2INT(flag);\n    break;\n  default:\n    rb_bug(\"rb_dlhandle_new\");\n  }\n\n  ptr = dlopen(clib, cflag);\n#if defined(HAVE_DLERROR)\n  if( !ptr && (err = dlerror()) ){\n    rb_raise(rb_eDLError, \"%s\", err);\n  }\n#else\n  if( !ptr ){\n    err = dlerror();\n    rb_raise(rb_eDLError, \"%s\", err);\n  }\n#endif\n  Data_Get_Struct(self, struct dl_handle, dlhandle);\n  if( dlhandle->ptr && dlhandle->open && dlhandle->enable_close ){\n    dlclose(dlhandle->ptr);\n  }\n  dlhandle->ptr = ptr;\n  dlhandle->open = 1;\n  dlhandle->enable_close = 0;\n\n  if( rb_block_given_p() ){\n    rb_ensure(rb_yield, self, rb_dlhandle_close, self);\n  }\n\n  return Qnil;\n}",
        },
        {
            "func": "bool SSecurityPlain::processMsg(SConnection* sc)\n{\n  rdr::InStream* is = sc->getInStream();\n  char* pw;\n  char *uname;\n  CharArray password;\n\n  if (!valid)\n    throw AuthFailureException(\"No password validator configured\");\n\n  if (state == 0) {\n    if (!is->checkNoWait(8))\n      return false;\n    ulen = is->readU32();\n    plen = is->readU32();\n    state = 1;\n  }\n\n  if (state == 1) {\n    if (!is->checkNoWait(ulen + plen))\n      return false;\n    state = 2;\n    pw = new char[plen + 1];\n    uname = new char[ulen + 1];\n    username.replaceBuf(uname);\n    password.replaceBuf(pw);\n    is->readBytes(uname, ulen);\n    is->readBytes(pw, plen);\n    pw[plen] = 0;\n    uname[ulen] = 0;\n    plen = 0;\n    if (!valid->validate(sc, uname, pw))\n      throw AuthFailureException(\"invalid password or username\");\n  }\n\n  return true;\n}",
            "func_before": "bool SSecurityPlain::processMsg(SConnection* sc)\n{\n  rdr::InStream* is = sc->getInStream();\n  char* pw;\n  char *uname;\n  CharArray password;\n\n  if (!valid)\n    throw AuthFailureException(\"No password validator configured\");\n\n  if (state == 0) {\n    if (!is->checkNoWait(8))\n      return false;\n    ulen = is->readU32();\n    plen = is->readU32();\n    state = 1;\n  }\n\n  if (state == 1) {\n    if (is->checkNoWait(ulen + plen + 2))\n      return false;\n    state = 2;\n    pw = new char[plen + 1];\n    uname = new char[ulen + 1];\n    username.replaceBuf(uname);\n    password.replaceBuf(pw);\n    is->readBytes(uname, ulen);\n    is->readBytes(pw, plen);\n    pw[plen] = 0;\n    uname[ulen] = 0;\n    plen = 0;\n    if (!valid->validate(sc, uname, pw))\n      throw AuthFailureException(\"invalid password or username\");\n  }\n\n  return true;\n}",
        },
        {
            "func": "static MagickBooleanType SkipDXTMipmaps(Image *image,DDSInfo *dds_info,\n  int texel_size,ExceptionInfo *exception)\n{\n  register ssize_t\n    i;\n\n  MagickOffsetType\n    offset;\n\n  size_t\n    h,\n    w;\n\n  /*\n    Only skip mipmaps for textures and cube maps\n  */\n  if (EOFBlob(image) != MagickFalse)\n    {\n      ThrowFileException(exception,CorruptImageError,\"UnexpectedEndOfFile\",\n        image->filename);\n      return(MagickFalse);\n    }\n  if (dds_info->ddscaps1 & DDSCAPS_MIPMAP\n      && (dds_info->ddscaps1 & DDSCAPS_TEXTURE\n          || dds_info->ddscaps2 & DDSCAPS2_CUBEMAP))\n    {\n      w = DIV2(dds_info->width);\n      h = DIV2(dds_info->height);\n\n      /*\n        Mipmapcount includes the main image, so start from one\n      */\n      for (i = 1; (i < (ssize_t) dds_info->mipmapcount) && w && h; i++)\n      {\n        offset = (MagickOffsetType) ((w + 3) / 4) * ((h + 3) / 4) * texel_size;\n        (void) SeekBlob(image, offset, SEEK_CUR);\n\n        w = DIV2(w);\n        h = DIV2(h);\n      }\n    }\n  return(MagickTrue);\n}",
            "func_before": "static MagickBooleanType SkipDXTMipmaps(Image *image,DDSInfo *dds_info,\n  int texel_size,ExceptionInfo *exception)\n{\n  register ssize_t\n    i;\n\n  MagickOffsetType\n    offset;\n\n  size_t\n    h,\n    w;\n\n  /*\n    Only skip mipmaps for textures and cube maps\n  */\n  if (dds_info->ddscaps1 & DDSCAPS_MIPMAP\n      && (dds_info->ddscaps1 & DDSCAPS_TEXTURE\n          || dds_info->ddscaps2 & DDSCAPS2_CUBEMAP))\n    {\n      if (EOFBlob(image) != MagickFalse)\n        {\n          ThrowFileException(exception,CorruptImageError,\"UnexpectedEndOfFile\",\n            image->filename);\n          return(MagickFalse);\n        }\n      w = DIV2(dds_info->width);\n      h = DIV2(dds_info->height);\n\n      /*\n        Mipmapcount includes the main image, so start from one\n      */\n      for (i = 1; (i < (ssize_t) dds_info->mipmapcount) && w && h; i++)\n      {\n        offset = (MagickOffsetType) ((w + 3) / 4) * ((h + 3) / 4) * texel_size;\n        (void) SeekBlob(image, offset, SEEK_CUR);\n\n        w = DIV2(w);\n        h = DIV2(h);\n      }\n    }\n  return(MagickTrue);\n}",
        }
    ]
}


def print_diff(func, func_before):
    """Print the unified diff between two code strings"""
    diff = difflib.unified_diff(
        func_before.split('\n'),
        func.split('\n'),
        n=1000000  # Set to a very large number to show all context
    )
    return diff


def get_information_from_example(func_before, func):
    diff = print_diff(func, func_before)
    n = 0
    line_number_sequence = []
    vulnerable_hunk = []
    for line in diff:
        print(line)
        if line.startswith('+'):
            line_number_sequence.append('[ADD]')
        elif line.startswith('-'):
            line_number_sequence.append('[' + str(n) + ']')
            vulnerable_hunk.append(line)
        elif line.startswith('?'):
            pass
        else:
            line_number_sequence.append(str(n))
        n += 1
    return line_number_sequence, vulnerable_hunk


def get_prompt(function, line, crash_free_constrain, number, vulnerability_type='Out-of-bounds Read'):
    example1 = prompt_example[type][0]
    example2 = prompt_example[type][1]
    line_number_sequence_1, vulnerable_hunk_1 = get_information_from_example(example1['func_before'], example1['func'])
    line_number_sequence_2, vulnerable_hunk_2 = get_information_from_example(example2['func_before'], example2['func'])
    return iterative_function.format(
        Vulnerable_Function_1=example1['func_before'],
        Vulnerable_Hunk_Locations_1=vulnerable_hunk_1,
        GroundTruth_Patch_Hunk_Location_Sequence_1=line_number_sequence_1,
        Patch_Function_1=example1['func'],
        Vulnerable_Function_2=example2['func_before'],
        Vulnerable_Hunk_Locations_2=vulnerable_hunk_2,
        GroundTruth_Patch_Hunk_Location_Sequence_2=line_number_sequence_2,
        Patch_Function_2=example2['func'],
        function=function,  # These placeholders need actual values when using the prompt
        line=line,
        number=number
    )


def get_function_from_file(file_path, line_number):
    parser = Parser()
    parser.set_language(C_LANGUAGE)

    with open(file_path, 'r', encoding='utf-8') as f:
        code = f.read()

    tree = parser.parse(bytes(code, 'utf-8'))
    root_node = tree.root_node

    def get_function_node(node, line_number):
        if node.type == 'function_definition':
            start_line = node.start_point[0]
            end_line = node.end_point[0]
            if start_line <= line_number <= end_line:
                return start_line, end_line
        for child in node.children:
            result = get_function_node(child, line_number)
            if result:
                return result
        return None

    results = get_function_node(root_node, line_number)
    if results:
        start_line = results[0]
        end_line = results[1]
        indent = ' ' * (len(code.split('\n')[start_line]) - len(code.split('\n')[start_line].lstrip()))

        function_code = '\n'.join(code.split('\n')[start_line:end_line + 1])
        # 去除function_code中每一行的第一个indent
        for i in range(len(function_code.split('\n'))):
            if function_code.split('\n')[i].startswith(indent):
                function_code.split('\n')[i] = function_code.split('\n')[i][len(indent):]
        return start_line, end_line, function_code, code.split('\n')[line_number - 1][len(indent):], indent
    else:
        return None


def generate_candidates(patch, source_file_path, start_line, end_line, first_indent):
    with open(source_file_path, 'r', encoding='utf-8') as f:
        code = f.read()
        original_lines = code.split('\n')
        patch_lines = original_lines[0:start_line] + [first_indent + line for line in
                                                      patch.split('\n')] + original_lines[end_line + 1:]
        _, patch_filename = tempfile.mkstemp(suffix=".c")
        # 将补丁内容写入刚刚创建的临时文件中。
        with open(patch_filename, "w", encoding='utf-8') as fh:
            fh.write('\n'.join(patch_lines))

        if os.path.exists("/tmp/diff.patch"):
            os.remove("/tmp/diff.patch")
        command = f"diff -Naur {source_file_path} {patch_filename} > /tmp/diff.patch"
        # try:
        subprocess.call(
            command,
            shell=True,
        )
        # finally:
        #     os.remove(patch_filename)
        with open("/tmp/diff.patch", 'r', encoding='utf-8') as f:
            diff_str = f.read()
            # 删除diff中以'---'或'+++'开头的行
            diff_str = '\n'.join(
                [line for line in diff_str.split('\n') if
                 not (line.startswith('---') or line.startswith('+++'))])
    return diff_str


# def get_sub_block(function, number):
#     parser = Parser()
#     parser.set_language(C_LANGUAGE)
#     tree = parser.parse(bytes(function, 'utf-8'))
#     root_node = tree.root_node
#
#     def get_node(node, line_number):
#         if node.start_point[0] + 1 <= line_number <= node.end_point[0] + 1:
#             return node
#         for child in node.children:
#             result = get_node(child, line_number)
#             if result:
#                 return result
#         return None
#
#     target_node = get_node(root_node, number)
#     start_line = target_node.start_point[0] + 1
#     end_line = target_node.end_point[0] + 1
#     function_lines = function.split('\n')
#     if target_node and '\n' in function[target_node.start_byte:target_node.end_byte]:
#         start_line = target_node.start_point[0] + 1
#         end_line = target_node.end_point[0] + 1
#         function_lines = function.split('\n')
#         # 使用一个字符串indent来存储sub_block的第一行的缩进
#         indent = ' ' * (len(function_lines[start_line - 1]) - len(function_lines[start_line - 1].lstrip()))
#         # 去除sub_block中每一行的缩进
#         for i in range(len(function_lines)):
#             if function_lines[i].startswith(indent):
#                 function_lines[i] = function_lines[i][len(indent):]
#
#         sub_block = '\n'.join(function_lines[start_line - 1:end_line])
#         return sub_block, start_line, end_line, indent
#     elif target_node and '\n' not in function[target_node.start_byte:target_node.end_byte]:
#         parent_node = target_node.parent
#         start_line = parent_node.start_point[0] + 1
#         end_line = parent_node.end_point[0] + 1
#         function_lines = function.split('\n')
#         # 使用一个字符串indent来存储sub_block的第一行的缩进
#         indent = ' ' * (len(function_lines[start_line - 1]) - len(function_lines[start_line - 1].lstrip()))
#         # 去除sub_block中每一行的缩进
#         for i in range(len(function_lines)):
#             if function_lines[i].startswith(indent):
#                 function_lines[i] = function_lines[i][len(indent):]
#         sub_block = '\n'.join(function_lines[start_line - 1:end_line])
#         return sub_block, start_line, end_line, indent
#     # 如果最终没有任何结果，就返回原函数
#     indent = ' ' * (len(function.split('\n')[0]) - len(function.split('\n')[0].lstrip()))
#     return function, 1, len(function.split('\n')), indent

def generate_use_llms_from_localization_list(localization_list, vulnerability_type, output_path):
    logger.info(f"Generating candidates from localization dict")
    total_candidates = []
    patch_id = 0
    for i in localization_list:
        vulnerable_file_path = i['location'].split(':')[0]
        line_number = int(i['location'].split(':')[1])
        crash_free_constrain = i['constraint']
        # token_number = int(i['location'].split(':')[2])
        results = get_function_from_file(vulnerable_file_path, line_number)
        if results:
            start_line = results[0]
            end_line = results[1]
            function = results[2]
            vulnerable_line = results[3]  # 代表漏洞代码语句，非行号
            indent = results[4]

            # prompt = iterative_function.format(
            #     function=function,
            #     line=vulnerable_line,
            #     vulnerability_type=vulnerability_type,
            #     crash_free_constrain=crash_free_constrain,
            #     number=line_number - start_line + 1
            # )
            prompt = get_prompt(
                function=function,
                line=vulnerable_line,
                vulnerability_type=vulnerability_type,
                crash_free_constrain=crash_free_constrain,
                number=line_number - start_line + 1
            )
            for _ in range(5):
                answers = get_response(prompt)
                if '```c' in answers and '```' in answers:
                    patch = answers[answers.find('```c') + 4:answers.rfind('```')]
                else:
                    patch = answers
                if '\\ No newline at end of file' in patch:
                    patch = patch.replace('\\ No newline at end of file', '')
                diff = generate_candidates(
                    patch,
                    vulnerable_file_path,
                    start_line,
                    end_line,
                    indent
                )
                total_candidates.append({
                    'diff': diff,
                    'id': patch_id,
                    'location': i['location'],
                })
                patch_id += 1
    logger.info(f"total_candidates:#{total_candidates}")
    with open(output_path, 'w', encoding='utf-8') as f_1:
        f_1.write(json.dumps(total_candidates, ensure_ascii=False, indent=4))


def generate_use_llms_from_localization_path(localization_path: str, output_path: str):
    total_candidates = []
    patch_id = 0
    with open(localization_path, "r", encoding='utf-8') as fh:
        localization = json.loads(fh.read())
    for i in localization:
        vulnerable_file_path = i['location'].split(':')[0]
        line_number = int(i['location'].split(':')[1])
        # token_number = int(i['location'].split(':')[2])
        results = get_function_from_file(vulnerable_file_path, line_number)
        if results:
            start_line = results[0]
            end_line = results[1]
            function = results[2]
            vulnerable_line = results[3]  # 代表漏洞代码语句，非行号
            indent = results[4]

            prompt = repair_function.format(
                function=function,
                line=vulnerable_line,
                number=line_number - start_line + 1
            )
            for _ in range(5):
                answers = get_response(prompt)
                if '```c' in answers and '```' in answers:
                    patch = answers[answers.find('```c') + 4:answers.rfind('```')]
                else:
                    patch = answers
                if '\\ No newline at end of file' in patch:
                    patch = patch.replace('\\ No newline at end of file', '')
                diff = generate_candidates(
                    patch,
                    vulnerable_file_path,
                    start_line,
                    end_line,
                    indent
                )
                total_candidates.append({
                    'diff': diff,
                    'id': patch_id,
                    'location': i['location'],
                })
                patch_id += 1
    print("total_candidates:{}".format(total_candidates))
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(json.dumps(total_candidates, ensure_ascii=False, indent=4))

# if __name__ == '__main__':
#     file_path = './localization.json'
#     generate_use_llms(file_path, "./candidate.json")
