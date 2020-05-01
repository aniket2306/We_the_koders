from django.conf.urls import url
from .views import *
from django.urls import path


urlpatterns = [ url(r'^$', view=index, name='index'),
                url(r'^login/$', view=login_user, name='login'),
                url(r'^logout/$', view=logout_user, name='logout'),
                url(r'^signup/$', view=signup_user, name='signup'),
                url(r'^quizzes/$',view=QuizListView.as_view(),name='quiz_index'),
                url(r'^category/$',view=CategoriesListView.as_view(),name='quiz_category_list_all'),
                url(r'^category/(?P<category_name>[\w|\W-]+)/$',view=ViewQuizListByCategory.as_view(),name='quiz_category_list_matching'),
                url(r'^progress/$',view=QuizUserProgressView.as_view(),name='quiz_progress'),
                url(r'^marking/$',view=QuizMarkingList.as_view(),name='quiz_marking'),
                url(r'^marking/(?P<pk>[\d.]+)/$',view=QuizMarkingDetail.as_view(),name='quiz_marking_detail'),
                url(r'^(?P<slug>[\w-]+)/$',view=QuizDetailView.as_view(),name='quiz_start_page'),
                url(r'^(?P<quiz_name>[\w-]+)/take/$',view=QuizTake.as_view(),name='quiz_question'),
                
]
