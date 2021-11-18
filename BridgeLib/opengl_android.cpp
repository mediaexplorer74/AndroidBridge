#include "pch.h"

#define DLL_EXPORT
#include "opengl_android.h"
#include "tools.h"

void _ZN7android13egl_display_t3getEPv()
{
	DebugLog(__FUNCTION__"\n");
}

EGLBoolean eglPresentationTimeANDROID(EGLDisplay dpy, EGLSurface surface, EGLnsecsANDROID time)
{
	DebugLog(__FUNCTION__"\n");
	return EGL_TRUE;
}

EGLint eglDupNativeFenceFDANDROID(EGLDisplay dpy, EGLSyncKHR)
{
	DebugLog(__FUNCTION__"\n");
	return 0;
}

EGLBoolean eglDestroySyncKHR(EGLDisplay dpy, EGLSyncKHR sync)
{
	DebugLog(__FUNCTION__"(...)\n");
	return EGL_TRUE;
}

EGLint eglClientWaitSyncKHR(EGLDisplay dpy, EGLSyncKHR sync, EGLint flags, EGLTimeKHR timeout)
{
	DebugLog(__FUNCTION__"(...)\n");
	return 0;
}

EGLSyncKHR eglCreateSyncKHR(EGLDisplay dpy, EGLenum type, const EGLint *attrib_list)
{
	DebugLog(__FUNCTION__"(...)\n");
	return NULL;
}

EGLint eglWaitSyncKHR(EGLDisplay dpy, EGLSyncKHR sync, EGLint flags)
{
	DebugLog(__FUNCTION__"(...)\n");
	return 0;
}

EGLBoolean eglSwapBuffersWithDamageKHR(EGLDisplay dpy, EGLSurface draw, EGLint *rects, EGLint n_rects)
{
	DebugLog(__FUNCTION__"(...)\n");
	return EGL_TRUE;
}


void eglSetDamageRegionKHR(EGLDisplay dpy, EGLSurface surface, EGLint *rects, EGLint n_rects)
{
	DebugLog(__FUNCTION__"(...)\n");
}


void _Z13eglBeginFramePvS_(EGLDisplay dpy, EGLSurface surface)
{
	DebugLog(__FUNCTION__"\n");
}

const char* _Z35eglQueryStringImplementationANDROIDPvi(EGLDisplay dpy, EGLint name)
{
	DebugLog(__FUNCTION__"\n");
	return "";
}

GLubyte * _ZN7android34egl_get_string_for_current_contextEj(GLenum name)
{
	DebugLog(__FUNCTION__"(%d)\n", name);
	return (GLubyte*)"";
}

void _ZN7android15setGLDebugLevelEi(int level)
{
	DebugLog(__FUNCTION__"(%d)\n", level);
}



//egl_cache_t* egl_cache_t::get();
void* _ZN7android11egl_cache_t3getEv()
{
	DebugLog(__FUNCTION__"\n");
	return NULL;
}


void _ZN7android11egl_cache_t16setCacheFilenameEPKc(const char* filename)
{
	DebugLog(__FUNCTION__"(%s)\n", filename);
}

void glTexBufferRangeEXT(GLenum target, GLenum internalformat, GLuint buffer, GLintptr offset, GLsizeiptr size)
{
	DebugLog(__FUNCTION__"(%d)\n", target);
}

void glTexBufferEXT(GLenum target, GLenum internalformat, GLuint buffer)
{
	DebugLog(__FUNCTION__"(%d)\n", target);
}

void glPatchParameteriEXT(GLenum pname, GLint value)
{
	DebugLog(__FUNCTION__"(%d, %d)\n", pname, value);
}

void glPrimitiveBoundingBoxEXT(GLfloat minX, GLfloat minY, GLfloat minZ, GLfloat minW, GLfloat maxX, GLfloat maxY, GLfloat maxZ, GLfloat maxW)
{
	DebugLog(__FUNCTION__"(%f, %f)\n", minX, minY);
}

void glFramebufferTextureEXT(GLenum target, GLenum attachment, GLuint texture, GLint level)
{
	DebugLog(__FUNCTION__"(%d)\n", target);
}


GLboolean glIsEnablediEXT(GLenum target, GLuint index)
{
	DebugLog(__FUNCTION__"(%d, %d)\n", target, index);
	return GL_FALSE;
}


void glColorMaskiEXT(GLuint index, GLboolean r, GLboolean g, GLboolean b, GLboolean a)
{
	DebugLog(__FUNCTION__"(%d, %d)\n", index, r);
}

void glBlendFuncSeparateiEXT(GLuint buf, GLenum srcRGB, GLenum dstRGB, GLenum srcAlpha, GLenum dstAlpha)
{
	DebugLog(__FUNCTION__"(%d, %d)\n", buf, srcRGB);
}

void glBlendFunciEXT(GLuint buf, GLenum src, GLenum dst)
{
	DebugLog(__FUNCTION__"(%d, %d, %d)\n", buf, src, dst);
}

void glBlendEquationSeparateiEXT(GLuint buf, GLenum modeRGB, GLenum modeAlpha)
{
	DebugLog(__FUNCTION__"(%d, %d, %d)\n", buf, modeRGB, modeAlpha);
}

void glBlendEquationiEXT(GLuint buf, GLenum mode)
{
	DebugLog(__FUNCTION__"(%d, %d)\n", buf, mode);
}

void glDisableiEXT(GLenum target, GLuint index)
{
	DebugLog(__FUNCTION__"(%d, %d)\n", target, index);
}

void glEnableiEXT(GLenum target, GLuint index)
{
	DebugLog(__FUNCTION__"(%d, %d)\n", target, index);
}

void glCopyImageSubDataEXT(GLuint srcName, GLenum srcTarget, GLint srcLevel, GLint srcX, GLint srcY, GLint srcZ, GLuint dstName, GLenum dstTarget, GLint dstLevel, GLint dstX, GLint dstY, GLint dstZ, GLsizei srcWidth, GLsizei srcHeight, GLsizei srcDepth)
{
	DebugLog(__FUNCTION__"(%d, %d, ..)\n", srcName, srcTarget);
}

void glTexStorage3DMultisampleOES(GLenum target, GLsizei samples, GLenum internalformat, GLsizei width, GLsizei height, GLsizei depth, GLboolean fixedsamplelocations)
{
	DebugLog(__FUNCTION__"(%d, %d, ..)\n", target, samples);
}

void glMinSampleShadingOES(GLfloat value)
{
	DebugLog(__FUNCTION__"(%f)\n", value);
}

void glBlendBarrierKHR(void)
{
	DebugLog(__FUNCTION__"()\n");
}
void glGetSamplerParameterIuivEXT(GLuint sampler, GLenum pname, GLuint *params)
{
	DebugLog(__FUNCTION__"()\n");
}

void glGetSamplerParameterIivEXT(GLuint sampler, GLenum pname, GLint *params)
{
	DebugLog(__FUNCTION__"()\n");
}

void glSamplerParameterIuivEXT(GLuint sampler, GLenum pname, const GLuint *param)
{
	DebugLog(__FUNCTION__"()\n");
}

void glSamplerParameterIivEXT(GLuint sampler, GLenum pname, const GLint *param)
{
	DebugLog(__FUNCTION__"()\n");
}

void glGetTexParameterIuivEXT(GLenum target, GLenum pname, GLuint *params)
{
	DebugLog(__FUNCTION__"()\n");
}

void glGetTexParameterIivEXT(GLenum target, GLenum pname, GLint *params)
{
	DebugLog(__FUNCTION__"()\n");
}

void glTexParameterIuivEXT(GLenum target, GLenum pname, const GLuint *params)
{
	DebugLog(__FUNCTION__"()\n");
}

void glTexParameterIivEXT(GLenum target, GLenum pname, const GLint *params)
{
	DebugLog(__FUNCTION__"()\n");
}

void glStartTilingQCOM(GLuint x, GLuint y, GLuint width, GLuint height, GLbitfield preserveMask)
{
	DebugLog(__FUNCTION__"()\n");
}

void glEndTilingQCOM(GLbitfield preserveMask)
{
	DebugLog(__FUNCTION__"()\n");
}

GLenum glGetGraphicsResetStatus(void)
{
	DebugLog(__FUNCTION__"()\n");
	return 0;
}

void glDrawElementsInstancedBaseVertex(GLenum mode, GLsizei count, GLenum type, GLvoid *indices, GLsizei primcount, GLint basevertex)
{
	DebugLog(__FUNCTION__"()\n");
}

void glDrawRangeElementsBaseVertex(GLenum mode, GLuint start, GLuint end, GLsizei count, GLenum type, GLvoid *indices, GLint basevertex)
{
	DebugLog(__FUNCTION__"()\n");
}

void glDrawElementsBaseVertex(GLenum mode, GLsizei count, GLenum type, GLvoid *indices, GLint basevertex)
{
	DebugLog(__FUNCTION__"()\n");
}