

var TitleId = 0;
var BodyPostId = 1;


interface PostToModerate {
  pageId: string;
  pageName: string;
  id: number;
  status: string;
  type: string;
  cdati: string;
  approvedText?: string;
  unapprovedText?: string;
  userId: string;
  userDisplayName: string;
  numEditsToReview?: string;
  numHandledFlags?: number;
  numPendingFlags?: number;
  numPendingEditSuggestions?: number;
  pendingFlags?: any[];
  postHiddenAt?: string;
  postDeletedAt?: string;
  treeDeletedAt?: string;
}


interface Post {
  postId: number;
  parentId: number;
  multireplyPostIds: number[];
  authorId: string;
  authorFullName: string;
  authorUsername: string
  createdAt: number;
  lastEditAppliedAt: number;
  numEditors: number;
  numLikeVotes: number;
  numWrongVotes: number;
  numOffTopicVotes: number;
  numPendingEditSuggestions: number;
  isTreeDeleted: boolean;
  isPostDeleted: boolean;
  isTreeCollapsed: boolean;
  isPostCollapsed: boolean;
  isTreeClosed: boolean;
  isApproved: boolean;
  pinnedPosition: number;
  likeScore: number;
  childIdsSorted: number[];
  sanitizedHtml: string;
}


interface User {
  userId: string;
  isLoggedIn?: boolean;
  isAdmin?: boolean;
  isAuthenticated?: boolean;
  username?: string;
  fullName?: string;
  rolePageSettings: any;
  votes: any;
  unapprovedPosts: any;
  postIdsAutoReadLongAgo: number[];
  postIdsAutoReadNow: number[];
  marksByPostId: { [postId: number]: any };
}


interface Category {
  name: string;
  pageId: string;
  slug: string;
  subCategories: number[];
}


interface Topic {
  pageId: string;
  title: string;
  url: string;
  categoryId: string;
  numPosts: number;
  numLikes: number;
  numWrongs: number;
  createdEpoch: number;
  lastPostEpoch: number;
}


enum TopicSortOrder { BumpTime = 1, LikesAndBumpTime };


interface OrderOffset {
  sortOrder: TopicSortOrder;
  time?: number;
  numLikes?: number;
}


interface Store {
  now: number;
  siteStatus: string;
  pageId: string;
  pageRole: string;
  numPosts: number;
  numPostsExclTitle: number;
  isInEmbeddedCommentsIframe: boolean;
  categories: Category[];
  user: User;
  userSpecificDataAdded?: boolean;
  newUserAccountCreated?: boolean;
  rootPostId: number;
  allPosts: { [postId: number]: Post };
  topLevelCommentIdsSorted: number[];
  horizontalLayout: boolean;
  socialLinksHtml: string;

  // If quickUpdate is true only posts in postsToUpdate will be updated.
  quickUpdate: boolean;
  postsToUpdate: { [postId: number]: boolean };
}


interface SettingFromServer<T> {
  name: string;
  defaultValue: T;
  anyAssignedValue?: T;
}


interface Setting {  // rename to SettingToSave
  type: string;  // 'WholeSite' or 'PageTree' or 'SinglePage'
  pageId?: string;
  name: string;
  newValue: any;
}


interface SpecialContent {
  rootPageId: string;
  contentId: string;
  defaultText: string;
  anyCustomText?: string;
}
